import json
import logging
import re
import boto3
from typing import Dict, Any, List, Optional

logger = logging.getLogger()

class ExceptionHelper:
    """Helper class for managing rule exceptions."""
    
    def __init__(self, bucket_name: Optional[str] = None):
        """
        Initialize exception helper.
        
        Args:
            bucket_name: S3 bucket name containing exception rules (optional)
        """
        self.s3_client = boto3.client('s3')
        self.bucket_name = bucket_name
        self.exceptions_cache = None
        self.etag_hash = None
        
        # If no bucket name is provided, log a message and return
        if not self.bucket_name:
            logger.info("No bucket name provided for exceptions, exception handling will be disabled")
    
    def _load_exceptions(self) -> Dict[str, Any]:
        """
        Load exceptions from S3 bucket.
        
        Returns:
            Dict containing exception rules
        """
        # If no bucket name is provided, return empty dict
        if not self.bucket_name:
            return {}
            
        try:
            # Get the current ETag to check if the file has changed
            response = self.s3_client.head_object(
                Bucket=self.bucket_name,
                Key="exceptions.json"
            )
            current_etag = response.get('ETag', '')
            
            # If the file hasn't changed, return the cached exceptions
            if self.exceptions_cache and self.etag_hash == current_etag:
                return self.exceptions_cache
            
            # Get the exceptions file
            response = self.s3_client.get_object(
                Bucket=self.bucket_name,
                Key="exceptions.json"
            )
            
            # Parse the exceptions
            exceptions = json.loads(response['Body'].read().decode('utf-8'))
            
            # Update the cache
            self.exceptions_cache = exceptions
            self.etag_hash = current_etag
            
            logger.info(f"Loaded {len(exceptions)} exception rules")
            return exceptions
            
        except self.s3_client.exceptions.NoSuchKey:
            logger.info("No exceptions.json file found in sigma_rules folder, exception handling will be disabled")
            return {}
        except Exception as e:
            logger.warning(f"Error loading exceptions: {str(e)}, exception handling will be disabled")
            return {}
    
    def is_excluded(self, rule_title: str, event: Dict[str, Any]) -> bool:
        """
        Check if an event should be excluded based on exception rules.
        
        Args:
            rule_title: The title of the Sigma rule
            event: The event data
            
        Returns:
            bool: True if the event should be excluded, False otherwise
        """
        # If no bucket name is provided, no exceptions are applied
        if not self.bucket_name:
            return False
            
        # Load exceptions
        exceptions = self._load_exceptions()
        
        # Check if there are exceptions for this rule
        if rule_title not in exceptions:
            return False
        
        rule_exceptions = exceptions[rule_title]
        
        # Get actor from the event
        actor = event.get('actor', '')
        
        # If actor is not directly in the event, try to extract it
        if not actor and 'userIdentity' in event:
            user_identity = event.get('userIdentity', {})
            if user_identity.get('type') == 'IAMUser':
                actor = user_identity.get('arn', '')
            elif user_identity.get('type') == 'AssumedRole':
                actor = user_identity.get('arn', '')
            elif user_identity.get('type') == 'Root':
                actor = 'arn:aws:iam::root'
            elif user_identity.get('type') == 'AWSService':
                actor = user_identity.get('invokedBy', '')
            elif user_identity.get('type') == 'FederatedUser':
                actor = user_identity.get('arn', '')
        
        # Get source IP from the event
        source_ip = event.get('sourceIPAddress', '')
        
        # Check excluded actors
        if 'excludedActors' in rule_exceptions and actor:
            if actor in rule_exceptions['excludedActors']:
                logger.info(f"Event excluded: Actor '{actor}' in excludedActors list for rule '{rule_title}'")
                return True
        
        # Check excluded source IPs
        if 'excludedSourceIPs' in rule_exceptions and source_ip:
            if source_ip in rule_exceptions['excludedSourceIPs']:
                logger.info(f"Event excluded: Source IP '{source_ip}' in excludedSourceIPs list for rule '{rule_title}'")
                return True
        
        # Check excluded actor regex patterns
        if 'excludedActorsRegex' in rule_exceptions and actor:
            logger.debug(f"Checking actor '{actor}' against regex patterns for rule '{rule_title}': {rule_exceptions['excludedActorsRegex']}")
            for pattern in rule_exceptions['excludedActorsRegex']:
                try:
                    # Log the exact pattern for debugging
                    logger.debug(f"Testing regex pattern '{pattern}' against actor '{actor}'")
                    
                    # Validate regex pattern before using it
                    try:
                        regex_obj = re.compile(pattern)
                        is_match = bool(regex_obj.match(actor))
                    except re.error as e:
                        # Detailed error handling for regex compilation
                        error_msg = str(e)
                        position = getattr(e, 'pos', 0)
                        pattern_excerpt = pattern[:position] + " >>> ERROR HERE >>> " + pattern[position:] if position < len(pattern) else pattern + " >>> ERROR AT END"
                        logger.error(f"Invalid regex pattern in exceptions.json for rule '{rule_title}': '{pattern_excerpt}' - Error: {error_msg}")
                        continue
                    
                    if is_match:
                        logger.info(f"Event excluded: Actor '{actor}' matches regex pattern '{pattern}' for rule '{rule_title}'")
                        return True
                    else:
                        logger.debug(f"No match found for pattern '{pattern}' against actor '{actor}'")
                except Exception as e:
                    logger.warning(f"Exception while processing regex pattern '{pattern}': {str(e)}")
        
        return False
    
    def _get_actor_from_event(self, event: Dict[str, Any]) -> str:
        """
        Extract the actor (IAM user/role) from the event.
        
        Args:
            event: The CloudTrail event
            
        Returns:
            str: The actor ARN or empty string if not found
        """
        user_identity = event.get('userIdentity', {})
        
        # Check for IAM user
        if user_identity.get('type') == 'IAMUser':
            return user_identity.get('arn', '')
        
        # Check for IAM role
        if user_identity.get('type') == 'AssumedRole':
            return user_identity.get('arn', '')
        
        # Check for root account
        if user_identity.get('type') == 'Root':
            return 'arn:aws:iam::root'
        
        # Check for AWS service
        if user_identity.get('type') == 'AWSService':
            return user_identity.get('invokedBy', '')
        
        # Check for federated user
        if user_identity.get('type') == 'FederatedUser':
            return user_identity.get('arn', '')
        
        return ''