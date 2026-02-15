import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

logger = logging.getLogger()

class NotificationHelper:
    """Helper class for managing notification cooldowns."""
    
    def __init__(self, dynamodb_table):
        """
        Initialize the notification helper.
        
        Args:
            dynamodb_table: DynamoDB table for storing notification state
        """
        self.table = dynamodb_table
    
    def should_send_notification(self, rule_title: str, cooldown_minutes: int = 60) -> bool:
        """
        Check if a notification should be sent based on cooldown period.
        
        Args:
            rule_title: The title of the rule
            cooldown_minutes: Cooldown period in minutes
            
        Returns:
            bool: True if notification should be sent, False if in cooldown
        """
        try:
            # Query for the last notification time
            response = self.table.query(
                KeyConditionExpression='pk = :pk',
                ExpressionAttributeValues={
                    ':pk': f"NOTIFICATION#{rule_title}"
                }
            )
            
            items = response.get('Items', [])
            
            # If no previous notification, we can send one
            if not items:
                logger.info(f"No previous notification found for rule '{rule_title}', sending notification")
                return True
            
            # Get the last notification time
            last_notification = items[0]
            last_time_str = last_notification.get('lastNotificationTime')
            
            if not last_time_str:
                logger.info(f"No last notification time found for rule '{rule_title}', sending notification")
                return True
            
            # Parse the last notification time
            try:
                last_time = datetime.fromisoformat(last_time_str.replace('Z', '+00:00'))
                now = datetime.now(timezone.utc)
                
                # Calculate time since last notification
                time_since_last = now - last_time
                cooldown_period = timedelta(minutes=cooldown_minutes)
                
                # Check if cooldown period has elapsed
                if time_since_last >= cooldown_period:
                    logger.info(
                        f"Cooldown period ({cooldown_minutes} minutes) has elapsed for rule '{rule_title}'. "
                        f"Last notification was {time_since_last.total_seconds() / 60:.1f} minutes ago. "
                        f"Sending notification."
                    )
                    return True
                else:
                    remaining_minutes = (cooldown_period - time_since_last).total_seconds() / 60
                    logger.info(
                        f"Rule '{rule_title}' is in cooldown period. "
                        f"Last notification was {time_since_last.total_seconds() / 60:.1f} minutes ago. "
                        f"Cooldown period is {cooldown_minutes} minutes. "
                        f"Remaining cooldown: {remaining_minutes:.1f} minutes. "
                        f"Skipping notification."
                    )
                    return False
            except ValueError as e:
                logger.error(f"Error parsing last notification time: {str(e)}")
                return True 
                
        except Exception as e:
            logger.error(f"Error checking notification cooldown: {str(e)}")
            return True 
    
    def update_notification_time(self, rule_title: str) -> None:
        """
        Update the last notification time for a rule.
        
        Args:
            rule_title: The title of the rule
        """
        try:
            now = datetime.now(timezone.utc)
            now_iso = now.isoformat()
            
            # Create or update the notification record
            self.table.put_item(
                Item={
                    'pk': f"NOTIFICATION#{rule_title}",
                    'sk': 'LAST_NOTIFICATION',
                    'ruleTitle': rule_title,
                    'lastNotificationTime': now_iso,
                    'ttl': int((now + timedelta(days=30)).timestamp())  
                }
            )
            
            logger.info(f"Updated last notification time for rule '{rule_title}' to {now_iso}")
            
        except Exception as e:
            logger.error(f"Error updating notification time: {str(e)}") 