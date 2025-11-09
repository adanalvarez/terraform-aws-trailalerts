import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta, timezone
import boto3
import hashlib
import os
from cloudtrail_helpers import generate_cloudtrail_information_section
from email_helpers import generate_email_html, sns_send_email, ses_send_email
from ip_helpers import get_ip_information_section
from styles import generate_style
from dynamodb_helpers import DynamoDBHelper
from constants import SEVERITY_LEVELS, DEFAULT_WINDOW_MINUTES

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class CorrelationHelper:
    """Helper class for managing correlation rules and finding Sigma rule correlations."""

    def __init__(self, bucket_name: str):
        """Initialize correlation helper.
        
        Args:
            bucket_name: S3 bucket name containing correlation rules
        """
        self.s3_client = boto3.client('s3')
        self.bucket_name = bucket_name
        self.correlation_rules_cache = None
        self.etag_hash = None

    def _load_correlation_rules(self) -> List[Dict[str, Any]]:
        """Load correlation rules from S3 bucket."""
        try:
            if not self.bucket_name:
                logger.warning("No bucket name provided for correlation rules")
                return []

            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix='postprocessing_rules/'
            )
            
            if 'Contents' not in response:
                logger.warning(f"No postprocessing rules found in bucket {self.bucket_name}/postprocessing_rules/")
                return []
            
            # Use a dictionary to store unique rules based on sigmaRuleTitle and lookFor
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
                        # Only include rules with type "correlation"
                        if rule.get('type') == 'correlation':
                            # Create a unique key based on sigmaRuleTitle and lookFor
                            rule_key = f"{rule.get('sigmaRuleTitle')}_{rule.get('lookFor')}"
                            if rule_key not in unique_rules:
                                unique_rules[rule_key] = rule
                            else:
                                logger.warning(f"Duplicate rule found for {rule_key}, using first occurrence")
            
            return list(unique_rules.values())
            
        except Exception as e:
            logger.error(f"Failed to load correlation rules: {str(e)}")
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
        """Refresh the correlation rules cache if ETags have changed."""
        current_hash = self._compute_etag_hash()
        if current_hash is None:
            return

        if self.correlation_rules_cache is None or self.etag_hash != current_hash:
            logger.info("Detected changes in postprocessing rules, refreshing cache")
            self.correlation_rules_cache = self._load_correlation_rules()
            self.etag_hash = current_hash

    def find_correlations(self, event: Dict[str, Any], rule: Dict[str, Any], dynamodb_table) -> List[Dict[str, Any]]:
        """Find correlation matches for the given Sigma rule."""
        self._refresh_cache_if_needed()
        
        if not self.correlation_rules_cache:
            return []

        current_rule_title = rule.get('title')
        event_time = event.get('eventTime')
        
        if not current_rule_title or not event_time:
            return []

        matches = []
        for correlation_rule in self.correlation_rules_cache:
            logger.info(f"Checking correlation rule: {correlation_rule.get('sigmaRuleTitle')} against current rule {current_rule_title}")
            if (correlation_rule.get('sigmaRuleTitle') == current_rule_title and 
                correlation_rule.get('lookFor')):
                
                event_datetime = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                window_minutes = correlation_rule.get('windowMinutes', DEFAULT_WINDOW_MINUTES)
                window_start = (event_datetime - timedelta(minutes=window_minutes)).isoformat()
                
                # Add a small buffer to the end time to catch events happening almost simultaneously
                # Using a 5-second buffer ensures we catch events with nearly identical timestamps
                end_time_with_buffer = (event_datetime + timedelta(seconds=5)).isoformat()
                
                logger.info(f"lookfor: {correlation_rule['lookFor']}, window_start: {window_start}, event_time: {event_time}, end_time_with_buffer: {end_time_with_buffer}")
                
                try:
                    # Query for previous events that match the lookFor Sigma rule, using the buffered end time
                    response = dynamodb_table.query(
                        IndexName='sigmaRuleTitleIndex', 
                        KeyConditionExpression='sigmaRuleTitle = :title AND #ts BETWEEN :start AND :end',
                        ExpressionAttributeNames={'#ts': 'timestamp'},
                        ExpressionAttributeValues={
                            ':title': correlation_rule['lookFor'],
                            ':start': window_start,
                            ':end': end_time_with_buffer
                        }
                    )
                    
                    if response.get('Items'):
                        first_event = response['Items'][0]
                        logger.info(
                            f"Correlation found: Current rule '{current_rule_title}' at {event_time} "
                            f"correlates with previous rule '{correlation_rule['lookFor']}' at "
                            f"{first_event.get('timestamp')} (within {window_minutes} minutes)"
                        )
                        
                        matches.append({
                            'rule': correlation_rule,
                            'severity_adjustment': correlation_rule.get('severity_adjustment', 'high'),
                            'correlated_events': response['Items']
                        })
                        
                except Exception as e:
                    logger.error(f"Failed to query DynamoDB for correlations: {str(e)}")

        return matches

    def get_highest_severity_adjustment(self, event: Dict[str, Any], rule: Dict[str, Any], dynamodb_table) -> Optional[str]:
        """Get the highest severity adjustment from matching correlation rules."""
        matches = self.find_correlations(event, rule, dynamodb_table)
        if not matches:
            return None

        highest_severity = max(
            matches,
            key=lambda x: SEVERITY_LEVELS.get(x['severity_adjustment'], 0)
        )['severity_adjustment']

        return highest_severity

    def has_matching_rule(self, rule_title: str) -> bool:
        """
        Check if there's a matching correlation rule for the given rule title.
        
        Args:
            rule_title: The title of the Sigma rule
            
        Returns:
            bool: True if a matching rule is found, False otherwise
        """
        self._refresh_cache_if_needed()
        
        if not self.correlation_rules_cache:
            return False
        
        for rule in self.correlation_rules_cache:
            if rule.get('sigmaRuleTitle') == rule_title:
                return True
        
        return False
