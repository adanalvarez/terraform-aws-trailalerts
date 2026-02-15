import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from botocore.exceptions import ClientError

logger = logging.getLogger()

class DynamoDBHelper:
    def __init__(self, table):
        self.table = table

    def store_event(self, event: Dict[str, Any], rule: Dict[str, Any], event_type: str = "regular", max_retries: int = 3) -> None:
        """
        Store event in DynamoDB with retry logic.
        
        Args:
            event: The CloudTrail event to store
            rule: The Sigma rule metadata
            event_type: Type of event (regular, threshold, correlation)
            max_retries: Maximum number of retry attempts
            
        Raises:
            ClientError: If all retry attempts fail
        """
        now = datetime.utcnow()
        now_iso = now.isoformat()
        
        # Get actor from event
        actor = event.get("userIdentity", {}).get("arn", "unknown")
        rule_title = rule.get("title", "unknown")
        
        # Determine partition key based on event type
        if event_type == "threshold":
            # For threshold events, use THRESHOLD#{rule_title}#{actor} as pk
            pk = f"THRESHOLD#{rule_title}#{actor}"
            
            # Get TTL from rule if available, otherwise use default (5 minutes)
            ttl_seconds = rule.get("ttlSeconds", 300)
            ttl_time = now + timedelta(seconds=ttl_seconds)
            ttl_timestamp = int(ttl_time.replace(tzinfo=timezone.utc).timestamp())
            logger.info(f"Storing THRESHOLD event: rule='{rule_title}', actor='{actor}', TTL={ttl_seconds}s")
        elif event_type == "correlation":
            # For correlation events, use CORRELATION#{actor} as pk
            pk = f"CORRELATION#{actor}"
            
            # Use longer TTL for correlation events (30 days)
            ttl_time = now + timedelta(days=30)
            ttl_timestamp = int(ttl_time.replace(tzinfo=timezone.utc).timestamp())
            logger.info(f"Storing CORRELATION event: actor='{actor}', TTL=30 days")
        else:
            # For regular events, use EVENT as pk
            pk = "EVENT"
            
            # Use standard TTL for regular events (30 days)
            ttl_time = now + timedelta(days=30)
            ttl_timestamp = int(ttl_time.replace(tzinfo=timezone.utc).timestamp())
            logger.info(f"Storing REGULAR event: rule='{rule_title}', actor='{actor}', TTL=30 days")

        # Generate sort key with timestamp and unique ID
        sk = f"{now_iso}#{uuid.uuid4().hex[:6]}"

        item = {
            "pk": pk,
            "sk": sk,
            "sourceType": rule.get("logsource", {}).get("service", "unknown"),
            "eventName": event.get("eventName", "unknown"),
            "timestamp": event.get("eventTime", now_iso),
            "actor": actor,
            "target": self._extract_target(event),
            "accountId": event.get("recipientAccountId", "unknown"),
            "severity": rule.get("level", "info"),
            "sourceIp": event.get("sourceIPAddress", "unknown"),
            "userAgent": event.get("userAgent", "unknown"),
            "sigmaRuleId": rule.get("id", "unknown"),
            "sigmaRuleTitle": rule.get("title", "unknown"),
            "rawEvent": json.dumps(event),
            "ttl": ttl_timestamp, 
            "eventType": event_type 
        }

        for attempt in range(max_retries):
            try:
                logger.info(f"Storing {event_type} event in DynamoDB (attempt {attempt + 1}/{max_retries})")
                logger.info(f"  Rule: {rule_title}")
                logger.info(f"  Actor: {actor}")
                logger.info(f"  Event: {event.get('eventName', 'unknown')}")
                logger.info(f"  Timestamp: {event.get('eventTime', now_iso)}")
                logger.info(f"  TTL: {ttl_timestamp} ({ttl_time.isoformat()})")
                
                self.table.put_item(Item=item)
                logger.info(f"{event_type} event stored successfully")
                return
            except ClientError as e:
                if attempt == max_retries - 1:
                    logger.error(f"Failed to store {event_type} event after max retries", extra={"error": str(e)})
                    raise
                logger.warning(f"Retry {attempt + 1}/{max_retries} after DynamoDB error", extra={"error": str(e)})

    def _extract_target(self, event: Dict[str, Any]) -> str:
        """
        Extract a meaningful target from the CloudTrail event.
        
        Args:
            event: The CloudTrail event
            
        Returns:
            String representing the target of the event
        """
        try:
            if "requestParameters" in event:
                for key, value in event["requestParameters"].items():
                    if isinstance(value, str):
                        return value
            if "resources" in event and isinstance(event["resources"], list):
                for res in event["resources"]:
                    return res.get("ARN") or res.get("name", "unknown")
        except Exception as e:
            logger.warning("Failed to extract target", extra={"error": str(e)})
        return "unknown" 