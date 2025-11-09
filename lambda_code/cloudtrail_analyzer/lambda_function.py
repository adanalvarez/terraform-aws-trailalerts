import json
import boto3
import gzip
import os
import logging
import yaml
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple
from sigma_matcher import matches_sigma_rule

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sqs = boto3.client('sqs')
s3_client = boto3.client('s3')

SQS_QUEUE_URL = os.environ['SQS_QUEUE_URL']
TRAILALERTS_BUCKET = os.environ['TRAILALERTS_BUCKET']

# Module-level caches
sigma_rules_cache: Optional[List[Dict[str, Any]]] = None
sigma_rules_etag_hash: Optional[str] = None
last_s3_list_time: float = 0 
s3_list_cache: Optional[List[Dict[str, Any]]] = None 
S3_LIST_CACHE_TTL = 300


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
    Updates the global sigma_rules_cache and sigma_rules_etag_hash.
    """
    global sigma_rules_cache, sigma_rules_etag_hash

    try:
        current_etag_hash = compute_s3_files_hash(TRAILALERTS_BUCKET)
        if sigma_rules_cache is None or sigma_rules_etag_hash != current_etag_hash:
            logger.info("Reloading Sigma rules from S3...")
            sigma_rules_cache = load_sigma_rules(TRAILALERTS_BUCKET)
            sigma_rules_etag_hash = current_etag_hash
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


def process_cloudtrail_records(content: str) -> None:
    """
    Process CloudTrail records and match them against Sigma rules.
    
    Args:
        content: JSON string containing CloudTrail records
        
    Example:
        >>> process_cloudtrail_records('{"Records": [...]}')
    """
    try:
        records = json.loads(content).get('Records', [])
        for record in records:
            logger.debug("Processing record: %s", json.dumps(record.get('eventName', 'Unknown')))
            for rule in sigma_rules_cache:
                if matches_sigma_rule(record, rule):
                    send_match_to_sqs(rule, record)
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON content: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing CloudTrail records: {str(e)}")


def send_match_to_sqs(rule: Dict[str, Any], record: Dict[str, Any]) -> None:
    """
    Send a matched event to the SQS queue.
    
    Args:
        rule: The matched Sigma rule
        record: The matched CloudTrail record
        
    Example:
        >>> send_match_to_sqs({'id': '1', 'title': 'Test Rule'}, {'eventName': 'CreateUser'})
    """
    try:
        # Create a clean copy of the rule to avoid any potential serialization issues
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
            "matched_event": record_copy,  # Use the modified record with sigmaEventSource
            "sigma_rule_data": rule_copy
        }
        
        response = sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=json.dumps(message_body)
        )
        logger.info(f"Match found: {rule.get('title', 'Unknown')}. SQS MessageId: {response['MessageId']}")
    except Exception as e:
        logger.error(f"Error sending match to SQS: {str(e)}")


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
