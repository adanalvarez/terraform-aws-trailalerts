import json
import boto3
import gzip
import os
import logging
import yaml
import hashlib
import time
import uuid
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple, Set
from sigma_matcher import matches_sigma_rule

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sqs = boto3.client('sqs')
s3_client = boto3.client('s3')

SQS_QUEUE_URL = os.environ['SQS_QUEUE_URL']
TRAILALERTS_BUCKET = os.environ['TRAILALERTS_BUCKET']

# SQS batch size limit
SQS_BATCH_SIZE = 10

# Module-level caches
sigma_rules_cache: Optional[List[Dict[str, Any]]] = None
sigma_rules_etag_hash: Optional[str] = None
last_s3_list_time: float = 0 
s3_list_cache: Optional[List[Dict[str, Any]]] = None 
S3_LIST_CACHE_TTL = 300

# Rule index: maps (eventSource, eventName) -> list of rules that could match
# Rules with no specific eventSource/eventName filter go into a wildcard list
rule_index: Optional[Dict[Tuple[str, str], List[Dict[str, Any]]]] = None
wildcard_rules: Optional[List[Dict[str, Any]]] = None


def build_rule_index(rules: List[Dict[str, Any]]) -> Tuple[Dict[Tuple[str, str], List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """
    Build an index of rules keyed by (eventSource, eventName) for fast lookup.
    
    Rules that specify both eventSource and eventName in any detection block
    are indexed under that key pair. Rules that don't specify one or both
    go into the wildcard list and are evaluated against every record.
    
    Args:
        rules: List of loaded Sigma rules
        
    Returns:
        Tuple of (indexed_rules dict, wildcard_rules list)
    """
    indexed: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    wildcards: List[Dict[str, Any]] = []
    
    for rule in rules:
        detection = rule.get('detection', {})
        if not detection:
            wildcards.append(rule)
            continue
        
        # Collect all eventSource and eventName values across all detection blocks
        # Only consider exact-match fields (no modifiers like |contains, |startswith, |re)
        event_sources: Set[str] = set()
        event_names: Set[str] = set()
        has_modifier_on_key_fields = False
        
        for block_name, block_criteria in detection.items():
            if block_name == 'condition':
                continue
            if not isinstance(block_criteria, dict):
                continue
            
            for field, value in block_criteria.items():
                base_field = field.split('|')[0].rstrip(':').strip()
                has_modifier = '|' in field
                
                # If eventSource or eventName use modifiers, this rule
                # cannot be safely indexed — fall back to wildcard
                if has_modifier and base_field in ('eventSource', 'eventName'):
                    has_modifier_on_key_fields = True
                    break
                
                if base_field == 'eventSource' and isinstance(value, str):
                    event_sources.add(value)
                elif base_field == 'eventName':
                    if isinstance(value, str):
                        event_names.add(value)
                    elif isinstance(value, list):
                        event_names.update(v for v in value if isinstance(v, str))
            
            if has_modifier_on_key_fields:
                break
        
        # Only index rules that specify BOTH eventSource and eventName exactly
        # and have no modifiers on these fields
        if event_sources and event_names and not has_modifier_on_key_fields:
            for source in event_sources:
                for name in event_names:
                    indexed[(source, name)].append(rule)
            logger.debug(f"Indexed rule '{rule.get('title', 'unknown')}' under {len(event_sources) * len(event_names)} key(s)")
        else:
            wildcards.append(rule)
            logger.debug(f"Rule '{rule.get('title', 'unknown')}' added to wildcard list (eventSource={bool(event_sources)}, eventName={bool(event_names)})")
    
    logger.info(
        f"Rule index built: {len(indexed)} key(s) covering "
        f"{sum(len(v) for v in indexed.values())} indexed rule entries, "
        f"{len(wildcards)} wildcard rule(s)"
    )
    return dict(indexed), wildcards


def list_s3_objects_cached(bucket_name: str, prefix: str) -> List[Dict[str, Any]]:
    """
    List objects in S3 bucket with caching to limit API calls.
    
    Args:
        bucket_name: Name of the S3 bucket
        prefix: S3 key prefix
        
    Returns:
        List of S3 object metadata
        
    Example:
        >>> objects = list_s3_objects_cached('my-bucket', 'sigma_rules/')
    """
    global last_s3_list_time, s3_list_cache
    
    current_time = time.time()
    
    # If cache is empty or older than TTL, refresh it
    if s3_list_cache is None or (current_time - last_s3_list_time) > S3_LIST_CACHE_TTL:
        logger.info(f"S3 list cache expired or empty. Refreshing objects list from {bucket_name}/{prefix}")
        try:
            response = s3_client.list_objects_v2(
                Bucket=bucket_name,
                Prefix=prefix
            )
            s3_list_cache = response.get('Contents', [])
            last_s3_list_time = current_time
        except Exception as e:
            logger.error(f"Error listing S3 objects: {str(e)}")
            if s3_list_cache is None:
                return []  
    else:
        logger.info(f"Using cached S3 object list (age: {int(current_time - last_s3_list_time)}s)")
    
    return s3_list_cache


def compute_s3_files_hash(bucket_name: str) -> str:
    """
    Compute a hash of all ETags in the S3 bucket.
    
    Args:
        bucket_name: Name of the S3 bucket
        
    Returns:
        SHA-256 hash of all ETags concatenated and sorted
        
    Example:
        >>> hash_value = compute_s3_files_hash('my-bucket')
        >>> print(hash_value)
        'a1b2c3d4...'
    """
    try:
        # Use cached list objects operation
        objects = list_s3_objects_cached(bucket_name, "sigma_rules/")
        etags = [obj['ETag'].strip('"') for obj in objects if 'ETag' in obj]
        return hashlib.sha256("".join(sorted(etags)).encode('utf-8')).hexdigest()
    except Exception as e:
        logger.error(f"Error computing S3 files hash: {str(e)}")
        return ""


def load_sigma_rules(bucket: str) -> List[Dict[str, Any]]:
    """
    Load all Sigma YAML rules from the S3 bucket.
    
    Args:
        bucket: Name of the S3 bucket containing Sigma rules
        
    Returns:
        List of loaded Sigma rules
        
    Example:
        >>> rules = load_sigma_rules('my-bucket')
        >>> print(len(rules))
        10
    """
    try:
        # Use cached list objects operation
        objects = list_s3_objects_cached(bucket, "sigma_rules/")
        sigma_rules = []

        for obj in objects:
            key = obj['Key']
            if key.endswith(('.yaml', '.yml')):
                logger.info(f"Loading Sigma rule: {key}")
                content = s3_client.get_object(Bucket=bucket, Key=key)['Body'].read().decode('utf-8')
                rules = yaml.safe_load(content)
                sigma_rules.extend(rules if isinstance(rules, list) else [rules])
        
        return sigma_rules
    except Exception as e:
        logger.error(f"Error loading Sigma rules: {str(e)}")
        return []


def reload_sigma_rules_if_needed() -> None:
    """
    Reload Sigma rules if the cache is empty or the bucket content has changed.
    Updates the global sigma_rules_cache, sigma_rules_etag_hash, and rule index.
    """
    global sigma_rules_cache, sigma_rules_etag_hash, rule_index, wildcard_rules

    try:
        current_etag_hash = compute_s3_files_hash(TRAILALERTS_BUCKET)
        if sigma_rules_cache is None or sigma_rules_etag_hash != current_etag_hash:
            logger.info("Reloading Sigma rules from S3...")
            sigma_rules_cache = load_sigma_rules(TRAILALERTS_BUCKET)
            sigma_rules_etag_hash = current_etag_hash
            # Rebuild the rule index whenever rules change
            rule_index, wildcard_rules = build_rule_index(sigma_rules_cache)
    except Exception as e:
        logger.error(f"Error reloading Sigma rules: {str(e)}")


def fetch_s3_object(bucket: str, key: str) -> str:
    """
    Fetch and decompress an S3 object if gzipped.
    
    Args:
        bucket: Name of the S3 bucket
        key: Key of the S3 object
        
    Returns:
        str: Decoded content of the S3 object
        
    Example:
        >>> content = fetch_s3_object('my-bucket', 'my-file.gz')
        >>> print(content[:100])
        '{"Records": [...]}'
    """
    try:
        content = s3_client.get_object(Bucket=bucket, Key=key)['Body'].read()
        try:
            return gzip.decompress(content).decode('utf-8')
        except OSError:
            return content.decode('utf-8')
    except Exception as e:
        logger.error(f"Error fetching S3 object: {str(e)}")
        return ""


def get_candidate_rules(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Get the list of candidate Sigma rules for a given CloudTrail record
    using the pre-built rule index.
    
    Returns indexed rules matching the record's (eventSource, eventName)
    plus all wildcard rules that must be checked against every record.
    
    Args:
        record: A single CloudTrail record
        
    Returns:
        List of Sigma rules that could potentially match this record
    """
    candidates = list(wildcard_rules) if wildcard_rules else []
    
    if rule_index:
        event_source = record.get('eventSource', '')
        event_name = record.get('eventName', '')
        key = (event_source, event_name)
        if key in rule_index:
            candidates.extend(rule_index[key])
    
    return candidates


def process_cloudtrail_records(content: str) -> None:
    """
    Process CloudTrail records and match them against Sigma rules.
    
    Uses the pre-built rule index to evaluate only candidate rules per record,
    and batches SQS messages for efficient sending.
    
    Args:
        content: JSON string containing CloudTrail records
        
    Example:
        >>> process_cloudtrail_records('{"Records": [...]}')
    """
    try:
        records = json.loads(content).get('Records', [])
        pending_messages: List[Dict[str, Any]] = []
        total_rules_evaluated = 0
        total_matches = 0
        
        for record in records:
            logger.debug("Processing record: %s", json.dumps(record.get('eventName', 'Unknown')))
            candidates = get_candidate_rules(record)
            total_rules_evaluated += len(candidates)
            
            for rule in candidates:
                if matches_sigma_rule(record, rule):
                    total_matches += 1
                    message = _build_sqs_message(rule, record)
                    pending_messages.append(message)
                    
                    # Flush when batch is full
                    if len(pending_messages) >= SQS_BATCH_SIZE:
                        _flush_sqs_batch(pending_messages)
                        pending_messages = []
        
        # Flush any remaining messages
        if pending_messages:
            _flush_sqs_batch(pending_messages)
        
        logger.info(
            f"Processed {len(records)} records, evaluated {total_rules_evaluated} "
            f"rule checks (vs {len(records) * len(sigma_rules_cache)} without index), "
            f"found {total_matches} match(es)"
        )
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON content: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing CloudTrail records: {str(e)}")


def _build_sqs_message(rule: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build an SQS message entry for a matched rule/record pair.
    
    Args:
        rule: The matched Sigma rule
        record: The matched CloudTrail record
        
    Returns:
        Dict containing Id and MessageBody for SQS batch sending
    """
    # Create a clean copy of the rule to avoid serialization issues
    rule_copy = {
        'id': rule.get('id'),
        'title': rule.get('title', 'Unknown Sigma Rule'),
        'level': rule.get('level', 'info'),
        'description': rule.get('description', ''),
        'logsource': rule.get('logsource', {}),
        'detection': rule.get('detection', {}),
        'status': rule.get('status', 'experimental')
    }
    
    # Add a sigmaEventSource field to identify this as a CloudTrail event
    record_copy = record.copy()
    record_copy["sigmaEventSource"] = "CloudTrail"
    
    message_body = {
        "sigma_rule_id": rule.get('id'),
        "sigma_rule_title": rule.get('title', 'Unknown Sigma Rule'),
        "matched_event": record_copy,
        "sigma_rule_data": rule_copy
    }
    
    return {
        'Id': uuid.uuid4().hex[:8],
        'MessageBody': json.dumps(message_body)
    }


MAX_SQS_RETRIES = 3


def _flush_sqs_batch(messages: List[Dict[str, Any]]) -> None:
    """
    Send a batch of messages to SQS (up to 10 per API call).
    Retries partially failed messages up to MAX_SQS_RETRIES times.
    
    Args:
        messages: List of SQS message entries with Id and MessageBody
        
    Raises:
        RuntimeError: If messages still fail after all retries
        Exception: If the SQS API call itself fails
    """
    if not messages:
        return
    
    try:
        to_send = messages
        for attempt in range(MAX_SQS_RETRIES):
            response = sqs.send_message_batch(
                QueueUrl=SQS_QUEUE_URL,
                Entries=to_send
            )
            
            successful = response.get('Successful', [])
            failed = response.get('Failed', [])
            
            if successful:
                logger.info(f"SQS batch sent: {len(successful)} message(s) delivered")
            
            if not failed:
                return
            
            # Log failures and prepare retry for failed messages
            failed_ids = {f['Id'] for f in failed}
            for failure in failed:
                logger.warning(
                    f"SQS batch message failed (attempt {attempt + 1}/{MAX_SQS_RETRIES}): "
                    f"Id={failure['Id']}, Code={failure['Code']}, Message={failure['Message']}"
                )
            to_send = [m for m in to_send if m['Id'] in failed_ids]
        
        # All retries exhausted — raise to trigger Lambda retry
        raise RuntimeError(
            f"SQS batch send failed after {MAX_SQS_RETRIES} retries: "
            f"{len(to_send)} message(s) could not be delivered"
        )
    except (RuntimeError):
        raise
    except Exception as e:
        logger.error(f"Error sending SQS batch ({len(messages)} messages): {str(e)}")
        raise


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, str]:
    """
    Lambda function entry point.
    
    Args:
        event: The Lambda event containing S3 records
        context: The Lambda context object
        
    Returns:
        Response containing status code and message
        
    Example:
        >>> response = lambda_handler({'Records': [...]}, None)
        >>> print(response)
        {'statusCode': '200', 'body': 'Event processed successfully'}
    """
    try:
        # Reload Sigma rules if needed
        reload_sigma_rules_if_needed()

        # Process each S3 event record
        for record in event.get('Records', []):
            try:
                bucket = record['s3']['bucket']['name']
                key = record['s3']['object']['key']
                logger.info(f"Processing S3 object: Bucket={bucket}, Key={key}")

                # Fetch and process the S3 object
                content = fetch_s3_object(bucket, key)
                process_cloudtrail_records(content)

            except KeyError as ke:
                logger.error(f"Missing key in record: {ke}")
            except Exception as record_exception:
                logger.error(f"Error processing record: {record_exception}")

    except Exception as e:
        logger.error(f"Unhandled error: {e}")
        return {'statusCode': '500', 'body': 'Error processing event'}

    return {'statusCode': '200', 'body': 'Event processed successfully'}
