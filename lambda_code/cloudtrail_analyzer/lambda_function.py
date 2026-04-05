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
    
    Loads each file independently so a single malformed rule file does not
    prevent other valid rules from being used.
    
    Args:
        bucket: Name of the S3 bucket containing Sigma rules
        
    Returns:
        List of loaded Sigma rules
        
    Raises:
        RuntimeError: If YAML rule files exist but none of them can be loaded
        Exception: If S3 access fails before any rule loading can occur
        
    Example:
        >>> rules = load_sigma_rules('my-bucket')
        >>> print(len(rules))
        10
    """
    # Use cached list objects operation
    objects = list_s3_objects_cached(bucket, "sigma_rules/")
    sigma_rules: List[Dict[str, Any]] = []
    yaml_files_seen = 0
    failed_files: List[str] = []

    for obj in objects:
        key = obj.get('Key', '')
        if not key.endswith(('.yaml', '.yml')):
            continue

        yaml_files_seen += 1
        logger.info(f"Loading Sigma rule: {key}")

        try:
            content = s3_client.get_object(Bucket=bucket, Key=key)['Body'].read().decode('utf-8')
            loaded_rules = yaml.safe_load(content)

            if loaded_rules is None:
                logger.warning(f"Sigma rule file is empty, skipping: {key}")
                continue

            if isinstance(loaded_rules, dict):
                sigma_rules.append(loaded_rules)
                continue

            if isinstance(loaded_rules, list):
                valid_rules = [rule for rule in loaded_rules if isinstance(rule, dict)]
                invalid_entries = len(loaded_rules) - len(valid_rules)
                if invalid_entries:
                    logger.warning(
                        f"Sigma rule file {key} contains {invalid_entries} non-dictionary rule entry(ies); skipping those entries"
                    )
                sigma_rules.extend(valid_rules)
                continue

            logger.warning(
                f"Sigma rule file {key} did not contain a rule object or list of rule objects; skipping"
            )
        except Exception as file_error:
            logger.exception(f"Error loading Sigma rule file {key}: {file_error}")
            failed_files.append(key)
            continue

    if yaml_files_seen == 0:
        logger.warning(f"No Sigma YAML files found in s3://{bucket}/sigma_rules/")
        return []

    if not sigma_rules:
        error_message = (
            f"No valid Sigma rules could be loaded from s3://{bucket}/sigma_rules/ "
            f"({yaml_files_seen} YAML file(s) scanned, {len(failed_files)} file(s) failed)"
        )
        logger.error(error_message)
        raise RuntimeError(error_message)

    if failed_files:
        logger.warning(
            f"Loaded {len(sigma_rules)} Sigma rule(s) while skipping {len(failed_files)} invalid file(s)"
        )
    else:
        logger.info(f"Loaded {len(sigma_rules)} Sigma rule(s) from {yaml_files_seen} YAML file(s)")

    return sigma_rules


def reload_sigma_rules_if_needed() -> None:
    """
    Reload Sigma rules if the cache is empty or the bucket content has changed.
    Updates the global sigma_rules_cache, sigma_rules_etag_hash, and rule index.

    If a refresh fails but a previously known-good cache exists, keep using that
    cache so detections continue instead of being disabled by a bad rule file.
    """
    global sigma_rules_cache, sigma_rules_etag_hash, rule_index, wildcard_rules

    current_etag_hash = compute_s3_files_hash(TRAILALERTS_BUCKET)
    if sigma_rules_cache is not None and sigma_rules_etag_hash == current_etag_hash:
        return

    logger.info("Reloading Sigma rules from S3...")
    previous_cache = sigma_rules_cache
    previous_hash = sigma_rules_etag_hash
    previous_index = rule_index
    previous_wildcards = wildcard_rules

    try:
        new_rules = load_sigma_rules(TRAILALERTS_BUCKET)
        sigma_rules_cache = new_rules
        sigma_rules_etag_hash = current_etag_hash
        # Rebuild the rule index whenever rules change
        rule_index, wildcard_rules = build_rule_index(sigma_rules_cache)
    except Exception as e:
        logger.error(f"Error reloading Sigma rules: {str(e)}")
        if previous_cache is not None:
            sigma_rules_cache = previous_cache
            sigma_rules_etag_hash = previous_hash
            rule_index = previous_index
            wildcard_rules = previous_wildcards
            logger.warning("Keeping last known good Sigma rules cache and index")
        else:
            raise


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
        logger.exception(f"Error fetching S3 object: {str(e)}")
        raise


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
        failed_records: List[str] = []
        total_rules_evaluated = 0
        total_matches = 0
        
        for index, record in enumerate(records, start=1):
            try:
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
            except Exception as record_exception:
                event_name = record.get('eventName', 'Unknown') if isinstance(record, dict) else 'Unknown'
                logger.exception(
                    f"Error processing CloudTrail record {index}/{len(records)} ({event_name}): {record_exception}"
                )
                failed_records.append(f"{event_name}: {record_exception}")
                continue
        
        # Flush any remaining messages
        if pending_messages:
            try:
                _flush_sqs_batch(pending_messages)
            except Exception as batch_exception:
                logger.exception(f"Error flushing final SQS batch: {batch_exception}")
                failed_records.append(f"SQS batch flush failed: {batch_exception}")
        
        logger.info(
            f"Processed {len(records)} records, evaluated {total_rules_evaluated} "
            f"rule checks (vs {len(records) * len(sigma_rules_cache or [])} without index), "
            f"found {total_matches} match(es)"
        )

        if failed_records:
            raise RuntimeError(
                f"Encountered {len(failed_records)} CloudTrail record processing failure(s); see logs for details"
            )
    except json.JSONDecodeError as e:
        logger.exception(f"Error decoding JSON content: {str(e)}")
        raise
    except Exception as e:
        logger.exception(f"Error processing CloudTrail records: {str(e)}")
        raise


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

        failed_s3_records: List[str] = []

        # Process each S3 event record
        for index, record in enumerate(event.get('Records', []), start=1):
            try:
                bucket = record['s3']['bucket']['name']
                key = record['s3']['object']['key']
                logger.info(f"Processing S3 object: Bucket={bucket}, Key={key}")

                # Skip non-CloudTrail-log objects (e.g. digest files, config snapshots)
                if 'CloudTrail-Digest' in key or not key.endswith('.json.gz'):
                    logger.info(f"Skipping non-CloudTrail log object: {key}")
                    continue

                # Fetch and process the S3 object
                content = fetch_s3_object(bucket, key)
                if not content or not content.strip():
                    logger.info(f"Skipping empty S3 object: Bucket={bucket}, Key={key}")
                    continue
                process_cloudtrail_records(content)

            except KeyError as ke:
                logger.exception(f"Missing key in S3 event record {index}: {ke}")
                failed_s3_records.append(f"record-{index}: missing key {ke}")
                continue
            except Exception as record_exception:
                logger.exception(f"Error processing S3 event record {index}: {record_exception}")
                failed_s3_records.append(f"record-{index}: {record_exception}")
                continue

        if failed_s3_records:
            raise RuntimeError(
                f"Failed to process {len(failed_s3_records)} S3 event record(s); see logs for details"
            )

    except Exception as e:
        logger.exception(f"Unhandled error: {e}")
        raise

    return {'statusCode': '200', 'body': 'Event processed successfully'}
