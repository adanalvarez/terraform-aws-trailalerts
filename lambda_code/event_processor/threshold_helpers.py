import json
import logging
import hashlib
import os
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class ThresholdHelper:
    """Helper class for managing threshold rules and finding threshold-based detections."""

    def __init__(self, bucket_name: str):
        """Initialize threshold helper.
        
        Args:
            bucket_name: S3 bucket name containing threshold rules
        """
        self.s3_client = boto3.client('s3')
        self.bucket_name = bucket_name
        self.threshold_rules_cache = None
        self.etag_hash = None

    def _load_threshold_rules(self) -> List[Dict[str, Any]]:
        """Load threshold rules from S3 bucket."""
        try:
            if not self.bucket_name:
                logger.warning("No bucket name provided for threshold rules")
                return []

            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix='postprocessing_rules/'
            )
            
            if 'Contents' not in response:
                logger.warning(f"No postprocessing rules found in bucket {self.bucket_name}/postprocessing_rules/")
                return []
            
            # Use a dictionary to store unique rules based on sigmaRuleTitle
            unique_rules = {}
            
            for obj in response.get('Contents', []):
                if obj['Key'].endswith('.json'):
                    logger.debug(f"Loading postprocessing rule file: {obj['Key']}")
                    content = self.s3_client.get_object(
                        Bucket=self.bucket_name,
                        Key=obj['Key']
                    )['Body'].read().decode('utf-8')
                    rules = json.loads(content)
                    
                    # Handle both single rule and list of rules
                    if not isinstance(rules, list):
                        rules = [rules]
                    
                    for rule in rules:
                        # Only include rules with type "threshold"
                        if rule.get('type') == 'threshold':
                            # Create a unique key based on sigmaRuleTitle
                            rule_key = rule.get('sigmaRuleTitle')
                            if rule_key not in unique_rules:
                                unique_rules[rule_key] = rule
                            else:
                                logger.warning(f"Duplicate rule found for {rule_key}, using first occurrence")
            
            return list(unique_rules.values())
            
        except Exception as e:
            logger.error(f"Failed to load threshold rules: {str(e)}")
            return []

    def _compute_etag_hash(self) -> str:
        """Compute a hash of all ETags in the postprocessing rules folder."""
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix='postprocessing_rules/'
            )
            etags = [obj['ETag'].strip('"') for obj in response.get('Contents', []) if 'ETag' in obj]
            return hashlib.sha256("".join(sorted(etags)).encode('utf-8')).hexdigest()
        except Exception as e:
            logger.error(f"Failed to compute ETags hash: {str(e)}")
            return None

    def _refresh_cache_if_needed(self) -> None:
        """Refresh the threshold rules cache if ETags have changed."""
        current_hash = self._compute_etag_hash()
        if current_hash is None:
            return

        if self.threshold_rules_cache is None or self.etag_hash != current_hash:
            logger.info("Detected changes in postprocessing rules, refreshing cache")
            self.threshold_rules_cache = self._load_threshold_rules()
            self.etag_hash = current_hash

    def find_threshold_matches(self, event: Dict[str, Any], rule: Dict[str, Any], dynamodb_table) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Check if the event exceeds the threshold for the given rule.
        
        Args:
            event: The CloudTrail event
            rule: The Sigma rule metadata
            dynamodb_table: DynamoDB table for querying events
            
        Returns:
            Tuple of (is_threshold_exceeded, severity_adjustment, threshold_info)
        """
        self._refresh_cache_if_needed()
        
        if not self.threshold_rules_cache:
            return False, None, None

        current_rule_title = rule.get('title')
        event_time = event.get('eventTime')
        actor = event.get('userIdentity', {}).get('arn', 'unknown')
        
        if not current_rule_title or not event_time or not actor:
            return False, None, None

        for threshold_rule in self.threshold_rules_cache:
            if threshold_rule.get('sigmaRuleTitle') == current_rule_title:
                threshold_count = threshold_rule.get('thresholdCount', 10)
                window_minutes = threshold_rule.get('windowMinutes', 5)
                severity_adjustment = threshold_rule.get('severity_adjustment', 'medium')
                
                event_datetime = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                window_start = (event_datetime - timedelta(minutes=window_minutes)).isoformat()
                
                try:
                    # Query for similar events by the same actor within the time window
                    logger.info(
                        f"Checking threshold for rule '{current_rule_title}': "
                        f"threshold={threshold_count}, window={window_minutes} minutes, "
                        f"actor='{actor}'"
                    )
                    
                    # First, query for all events with this rule title in the time window
                    response = dynamodb_table.query(
                        IndexName='sigmaRuleTitleIndex',
                        KeyConditionExpression='sigmaRuleTitle = :rule_title AND #ts BETWEEN :start AND :end',
                        ExpressionAttributeNames={
                            '#ts': 'timestamp'
                        },
                        ExpressionAttributeValues={
                            ':rule_title': current_rule_title,
                            ':start': window_start,
                            ':end': event_time
                        }
                    )
                    
                    # Then filter for the specific actor
                    actor_events = [item for item in response.get('Items', []) if item.get('actor') == actor]
                    
                    # Count includes the current event
                    event_count = len(actor_events) + 1
                    
                    logger.info(
                        f"Threshold check details: Found {len(response.get('Items', []))} total events for rule '{current_rule_title}', "
                        f"of which {len(actor_events)} are from actor '{actor}'"
                    )
                    
                    # Log details of each event for debugging
                    if actor_events:
                        logger.info(f"Events from actor '{actor}':")
                        for idx, event in enumerate(actor_events):
                            logger.info(f"  Event {idx+1}: {event.get('timestamp')} - {event.get('eventName')}")
                    else:
                        logger.info(f"No previous events found for actor '{actor}' in the time window")
                    
                    # Create threshold info for notification, regardless of whether threshold is exceeded
                    threshold_info = {
                        'eventCount': event_count,
                        'thresholdCount': threshold_count,
                        'windowMinutes': window_minutes,
                        'actor': actor,
                        'ruleTitle': current_rule_title
                    }
                    
                    if event_count >= threshold_count:
                        logger.info(
                            f"THRESHOLD EXCEEDED: Rule '{current_rule_title}' triggered {event_count} times "
                            f"by actor '{actor}' within {window_minutes} minutes (threshold: {threshold_count}). "
                            f"Adjusting severity to {severity_adjustment}"
                        )
                        return True, severity_adjustment, threshold_info
                    else:
                        logger.info(
                            f"Threshold NOT exceeded: Rule '{current_rule_title}' triggered {event_count} times "
                            f"by actor '{actor}' within {window_minutes} minutes (threshold: {threshold_count}). "
                            f"Severity will remain at {rule.get('level', 'info')}"
                        )
                    
                except Exception as e:
                    logger.error(f"Failed to query DynamoDB for threshold: {str(e)}")

        return False, None, None

    def has_matching_rule(self, rule_title: str) -> bool:
        """
        Check if there's a matching threshold rule for the given rule title.
        
        Args:
            rule_title: The title of the Sigma rule
            
        Returns:
            bool: True if a matching rule is found, False otherwise
        """
        self._refresh_cache_if_needed()
        
        if not self.threshold_rules_cache:
            return False
        
        for rule in self.threshold_rules_cache:
            if rule.get('sigmaRuleTitle') == rule_title:
                return True
        
        return False