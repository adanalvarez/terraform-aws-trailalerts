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

# SQS batch size limit
SQS_BATCH_SIZE = 10

# Module-level caches
sigma_rules_cache: Optional[List[Dict[str, Any]]] = None
sigma_rules_etag_hash: Optional[str] = None
last_s3_list_time: float = 0
s3_list_cache: Optional[List[Dict[str, Any]]] = None
S3_LIST_CACHE_TTL = 300

# Rule index for fast lookup
rule_index: Optional[Dict[Tuple[str, str], List[Dict[str, Any]]]] = None
wildcard_rules: Optional[List[Dict[str, Any]]] = None

# SQS batching constants
SQS_BATCH_SIZE = 10
MAX_SQS_RETRIES = 3

# SQS message counter for unique IDs
_sqs_msg_counter = 0


def list_s3_objects_cached(bucket_name: str, prefix: str) -> List[Dict[str, Any]]:
    """List objects in S3 bucket with caching and pagination."""
    global last_s3_list_time, s3_list_cache

    current_time = time.time()

    if s3_list_cache is None or (current_time - last_s3_list_time) > S3_LIST_CACHE_TTL:
        logger.info(f"S3 list cache expired or empty. Refreshing objects list from {bucket_name}/{prefix}")
        try:
            all_objects = []
            paginator = s3_client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
                all_objects.extend(page.get('Contents', []))
            s3_list_cache = all_objects
            last_s3_list_time = current_time
        except Exception as e:
            logger.error(f"Error listing S3 objects: {str(e)}")
            if s3_list_cache is None:
                return []
    else:
        logger.info(f"Using cached S3 object list (age: {int(current_time - last_s3_list_time)}s)")

    return s3_list_cache


def compute_s3_files_hash(bucket_name: str) -> str:
    """Compute a hash of all ETags in the S3 bucket."""
    try:
        objects = list_s3_objects_cached(bucket_name, "sigma_rules/")
        etags = [obj['ETag'].strip('"') for obj in objects if 'ETag' in obj]
        return hashlib.sha256("".join(sorted(etags)).encode('utf-8')).hexdigest()
    except Exception as e:
        logger.error(f"Error computing S3 files hash: {str(e)}")
        return ""


def _is_valid_sigma_rule(rule: Any) -> bool:
    """Return True when a parsed YAML document looks like a usable Sigma rule."""
    if not isinstance(rule, dict):
        return False

    detection = rule.get('detection')
    if not isinstance(detection, dict):
        return False

    condition = detection.get('condition', 'selection')
    if condition is not None and not isinstance(condition, str):
        return False

    return any(
        block_name != 'condition' and isinstance(block, dict)
        for block_name, block in detection.items()
    )


def _extract_valid_sigma_rules(parsed_yaml: Any, key: str) -> List[Dict[str, Any]]:
    """Normalize a YAML document or list of documents into validated Sigma rules."""
    documents = parsed_yaml if isinstance(parsed_yaml, list) else [parsed_yaml]
    valid_rules = []

    for index, rule in enumerate(documents):
        if _is_valid_sigma_rule(rule):
            valid_rules.append(rule)
        else:
            logger.error(f"Skipping invalid Sigma rule document in {key} at index {index}")

    return valid_rules


def load_sigma_rules(bucket: str) -> List[Dict[str, Any]]:
    """Load all Sigma YAML rules from S3, skipping individual bad files."""
    objects = list_s3_objects_cached(bucket, "sigma_rules/")
    sigma_rules = []
    errors = 0

    for obj in objects:
        key = obj['Key']
        if key.endswith(('.yaml', '.yml')):
            try:
                logger.info(f"Loading Sigma rule: {key}")
                content = s3_client.get_object(Bucket=bucket, Key=key)['Body'].read().decode('utf-8')
                rules = yaml.safe_load(content)
                valid_rules = _extract_valid_sigma_rules(rules, key)
                if not valid_rules:
                    errors += 1
                    continue
                sigma_rules.extend(valid_rules)
            except Exception as e:
                errors += 1
                logger.error(f"Error loading Sigma rule {key}: {e}")

    if errors and not sigma_rules:
        raise RuntimeError(f"No valid Sigma rules could be loaded from S3 ({errors} file(s) failed)")

    return sigma_rules


def build_rule_index(rules: List[Dict[str, Any]]) -> Tuple[Dict[Tuple[str, str], List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """Build an index of rules keyed by (eventSource, eventName) for fast lookup."""
    indexed: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    wildcards: List[Dict[str, Any]] = []

    for rule in rules:
        if not isinstance(rule, dict):
            logger.warning(f"Skipping non-dict Sigma rule during indexing: {type(rule)}")
            continue

        detection = rule.get('detection', {})
        if not isinstance(detection, dict) or not detection:
            wildcards.append(rule)
            continue

        event_sources: set = set()
        event_names: set = set()
        has_modifier = False
        has_any_block = False

        for block_name, block in detection.items():
            if not isinstance(block, dict):
                continue
            has_any_block = True

            for key in block:
                if key.startswith('eventSource|') or key.startswith('eventName|'):
                    has_modifier = True
                    break

            if has_modifier:
                break

            if 'eventSource' in block:
                src = block['eventSource']
                if isinstance(src, str):
                    event_sources.add(src)
                elif isinstance(src, list):
                    event_sources.update(s for s in src if isinstance(s, str))

            if 'eventName' in block:
                name = block['eventName']
                if isinstance(name, str):
                    event_names.add(name)
                elif isinstance(name, list):
                    event_names.update(n for n in name if isinstance(n, str))

        if has_modifier or not has_any_block or not event_sources or not event_names:
            wildcards.append(rule)
            continue

        for src in event_sources:
            for name in event_names:
                indexed.setdefault((src, name), []).append(rule)

    return indexed, wildcards


def get_candidate_rules(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get candidate rules for a record using the pre-built index."""
    candidates = []

    if rule_index is not None:
        key = (record.get('eventSource', ''), record.get('eventName', ''))
        candidates = list(rule_index.get(key, []))

    if wildcard_rules is not None:
        candidates.extend(wildcard_rules)

    return candidates


def reload_sigma_rules_if_needed() -> None:
    """Reload Sigma rules if cache is empty or bucket content changed."""
    global sigma_rules_cache, sigma_rules_etag_hash, rule_index, wildcard_rules

    previous_cache = sigma_rules_cache
    previous_hash = sigma_rules_etag_hash
    previous_index = rule_index
    previous_wildcards = wildcard_rules

    try:
        current_etag_hash = compute_s3_files_hash(TRAILALERTS_BUCKET)
        if sigma_rules_cache is None or sigma_rules_etag_hash != current_etag_hash:
            logger.info("Reloading Sigma rules from S3...")
            new_rules = load_sigma_rules(TRAILALERTS_BUCKET)
            sigma_rules_cache = new_rules
            sigma_rules_etag_hash = current_etag_hash
            rule_index, wildcard_rules = build_rule_index(new_rules)
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
    """Fetch and decompress an S3 object."""
    content = s3_client.get_object(Bucket=bucket, Key=key)['Body'].read()
    try:
        return gzip.decompress(content).decode('utf-8')
    except OSError:
        return content.decode('utf-8')


def _build_sqs_message(rule: Dict[str, Any], record: Dict[str, Any]) -> Dict[str, str]:
    """Build an SQS batch message entry for a matched event."""
    global _sqs_msg_counter
    _sqs_msg_counter += 1

    rule_copy = {
        'id': rule.get('id'),
        'title': rule.get('title', 'Unknown Sigma Rule'),
        'level': rule.get('level', 'info'),
        'description': rule.get('description', ''),
        'logsource': rule.get('logsource', {}),
        'detection': rule.get('detection', {}),
        'status': rule.get('status', 'experimental')
    }

    record_copy = record.copy()
    record_copy["sigmaEventSource"] = "CloudTrail"

    message_body = {
        "sigma_rule_id": rule.get('id'),
        "sigma_rule_title": rule.get('title', 'Unknown Sigma Rule'),
        "matched_event": record_copy,
        "sigma_rule_data": rule_copy
    }

    return {
        "Id": str(_sqs_msg_counter % 100000000),
        "MessageBody": json.dumps(message_body)
    }


def _flush_sqs_batch(messages: List[Dict[str, str]]) -> None:
    """Send a batch of messages to SQS with retry logic."""
    if not messages:
        return

    to_send = list(messages)
    for attempt in range(MAX_SQS_RETRIES):
        response = sqs.send_message_batch(
            QueueUrl=SQS_QUEUE_URL,
            Entries=to_send
        )
        failed = response.get('Failed', [])
        if not failed:
            logger.info(f"SQS batch: {len(messages)} messages sent successfully")
            return

        failed_ids = {f['Id'] for f in failed}
        to_send = [m for m in to_send if m['Id'] in failed_ids]
        logger.warning(f"SQS batch: {len(failed_ids)} messages failed (attempt {attempt + 1}/{MAX_SQS_RETRIES})")

    raise RuntimeError(
        f"SQS batch send failed after {MAX_SQS_RETRIES} retries, "
        f"{len(to_send)} messages remaining"
    )


def _count_indexed_rules() -> int:
    """Count distinct rules reachable through the fast lookup index."""
    if not rule_index:
        return 0
    return len({id(rule) for rules in rule_index.values() for rule in rules})


def _current_rule_metrics() -> Dict[str, int]:
    """Return low-cost rule cache/index counters for summary logging."""
    return {
        "rules_loaded": len(sigma_rules_cache or []),
        "indexed_rules": _count_indexed_rules(),
        "indexed_rule_keys": len(rule_index or {}),
        "wildcard_rules": len(wildcard_rules or []),
    }


def _log_processing_summary(summary: Dict[str, Any]) -> None:
    """Emit one structured summary line per processed CloudTrail object."""
    logger.info(json.dumps({"message": "cloudtrail_analyzer_summary", **summary}, sort_keys=True))


def process_cloudtrail_records(content: str) -> Dict[str, int]:
    """Process CloudTrail records against Sigma rules with batched SQS sending."""
    records = json.loads(content).get('Records', [])
    sqs_batch: List[Dict[str, str]] = []
    errors = 0
    metrics = {
        "cloudtrail_records_count": len(records),
        "candidate_count": 0,
        "matches": 0,
        "sqs_batches": 0,
        "sqs_messages_sent": 0,
        **_current_rule_metrics(),
    }

    def flush_batch() -> None:
        nonlocal sqs_batch
        if not sqs_batch:
            return
        batch_size = len(sqs_batch)
        _flush_sqs_batch(sqs_batch)
        metrics["sqs_batches"] += 1
        metrics["sqs_messages_sent"] += batch_size
        sqs_batch = []

    for record in records:
        try:
            logger.debug("Processing record: %s", record.get('eventName', 'Unknown'))
            candidate_rules = get_candidate_rules(record)
            metrics["candidate_count"] += len(candidate_rules)
            for rule in candidate_rules:
                if matches_sigma_rule(record, rule):
                    metrics["matches"] += 1
                    sqs_batch.append(_build_sqs_message(rule, record))
                    if len(sqs_batch) >= SQS_BATCH_SIZE:
                        flush_batch()
        except Exception as e:
            errors += 1
            logger.error(f"Error processing record: {e}")

    try:
        flush_batch()
    except Exception as e:
        raise RuntimeError(f"CloudTrail record processing failure: {e}") from e

    if errors:
        raise RuntimeError(f"{errors} CloudTrail record processing failure(s)")

    return metrics


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, str]:
    """Lambda function entry point."""
    reload_sigma_rules_if_needed()

    s3_errors = 0

    for record in event.get('Records', []):
        try:
            start_time = time.perf_counter()
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']

            if not key.endswith('.json.gz'):
                logger.info(f"Skipping non-log file: {key}")
                continue
            if 'CloudTrail-Digest' in key:
                logger.info(f"Skipping digest file: {key}")
                continue

            logger.info(f"Processing S3 object: Bucket={bucket}, Key={key}")
            content = fetch_s3_object(bucket, key)
            if not content:
                logger.warning(f"Empty content from S3 object: {key}")
                continue

            summary = process_cloudtrail_records(content) or {}
            summary.update({
                "bucket": bucket,
                "key": key,
                "duration_ms": int((time.perf_counter() - start_time) * 1000),
            })
            _log_processing_summary(summary)

        except KeyError as ke:
            s3_errors += 1
            logger.error(f"Missing key in record: {ke}")
        except Exception as record_exception:
            s3_errors += 1
            logger.error(f"Error processing S3 record: {record_exception}")

    if s3_errors:
        raise RuntimeError(f"Failed to process {s3_errors} S3 event record(s)")

    return {'statusCode': '200', 'body': 'Event processed successfully'}
