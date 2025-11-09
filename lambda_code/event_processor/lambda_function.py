import os
import json
import logging
import boto3
from typing import Any, Dict, List, Optional
from cloudtrail_helpers import generate_cloudtrail_information_section
from email_helpers import generate_email_html, sns_send_email, ses_send_email, generate_correlation_section, generate_sigma_rule_section, generate_threshold_section
from ip_helpers import get_ip_information_section
from styles import generate_style
from dynamodb_helpers import DynamoDBHelper
from correlation_helpers import CorrelationHelper
from threshold_helpers import ThresholdHelper
from notification_helpers import NotificationHelper
from exception_helpers import ExceptionHelper
from constants import SEVERITY_LEVELS, DEFAULT_MIN_SEVERITY
from datetime import datetime, timedelta

# Import plugin system
from plugins.registry import PluginRegistry
from plugins.config import PluginConfig

# Configure structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
dynamodb = boto3.resource("dynamodb")
table_name = os.environ.get("DYNAMODB_TABLE_NAME")
# Make DynamoDB table and helper optional
dynamodb_table = dynamodb.Table(table_name) if table_name else None
dynamodb_helper = DynamoDBHelper(dynamodb_table) if dynamodb_table else None

# Initialize helpers if bucket is configured
correlation_bucket = os.environ.get("CORRELATION_RULES_BUCKET")
correlation_helper = CorrelationHelper(correlation_bucket) if correlation_bucket else None
threshold_helper = ThresholdHelper(correlation_bucket) if correlation_bucket else None
exception_helper = ExceptionHelper(correlation_bucket) if correlation_bucket else None

# Initialize plugin system
plugin_registry = PluginRegistry()
plugin_config = PluginConfig()

# Required environment variables
REQUIRED_ENV_VARS = {
    "SOURCE_EMAIL": "Source email address for SES",
    "EMAIL_RECIPIENT": "Destination email address"
}

# Optional environment variables
OPTIONAL_ENV_VARS = {
    "DYNAMODB_TABLE_NAME": "DynamoDB table name for storing events (required for correlation/threshold)",
    "VPNAPI_KEY": "API key for VPN service",
    "SNS_TOPIC_ARN": "SNS topic ARN for notifications",
    "CORRELATION_RULES_BUCKET": "S3 bucket containing correlation and threshold rules",
    "CORRELATION_ENABLED": "Boolean to enable correlation and threshold processing",
    "NOTIFICATION_COOLDOWN_MINUTES": "Global cooldown period in minutes between notifications",
    "MIN_NOTIFICATION_SEVERITY": "Minimum severity level for sending notifications",
    "ENABLED_PLUGINS": "JSON array of enabled plugin names"
}

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, str]:
    """
    Lambda function entry point.
    
    Args:
        event: The Lambda event
        context: The Lambda context
        
    Returns:
        Dict containing status code and message
    """
    try:
        # Validate environment variables
        missing_vars = [var for var in REQUIRED_ENV_VARS if not os.environ.get(var)]
        if missing_vars:
            error_msg = f"Missing required environment variables: {', '.join(missing_vars)}"
            logger.error(error_msg)
            return {"statusCode": "500", "body": error_msg}
        
        # Log optional environment variables
        for var, description in OPTIONAL_ENV_VARS.items():
            if os.environ.get(var):
                logger.info(f"Using {var}: {description}")
            else:
                logger.info(f"Not using {var}: {description}")
        
        # Register plugins
        register_plugins()
        
        # Process SQS messages
        if "Records" in event:
            for record in event["Records"]:
                if record.get("eventSource") == "aws:sqs":
                    try:
                        # Parse the message body
                        message_body = json.loads(record.get("body", "{}"))
                        logger.debug(f"Received message body: {json.dumps(message_body)[:500]}...")
                        
                        # Initialize rule_metadata
                        rule_metadata = {}
                        
                        # Extract both formats of rule data
                        sigma_rule_data = message_body.get("sigma_rule_data")
                        sigma_rule_title = message_body.get("sigma_rule_title", "Unknown Rule")
                        sigma_rule_id = message_body.get("sigma_rule_id", "unknown")
                        
                        # If sigma_rule_data exists, try to use it
                        if sigma_rule_data is not None:
                            if isinstance(sigma_rule_data, str):
                                try:
                                    rule_metadata = json.loads(sigma_rule_data)
                                except json.JSONDecodeError:
                                    logger.error(f"Failed to parse sigma_rule_data as JSON: {sigma_rule_data[:100]}...")
                                    # Fall back to individual fields if parsing fails
                                    rule_metadata = {
                                        "title": sigma_rule_title,
                                        "id": sigma_rule_id,
                                        "level": "medium"  # Default level
                                    }
                            else:
                                # If it's already a dictionary, use it directly
                                rule_metadata = sigma_rule_data
                        else:
                            # If sigma_rule_data doesn't exist, use individual fields
                            rule_metadata = {
                                "title": sigma_rule_title,
                                "id": sigma_rule_id,
                                "level": "medium"  # Default level
                            }
                        
                        logger.info(f"Processing rule: {rule_metadata.get('title', 'unknown')} (ID: {rule_metadata.get('id', 'unknown')})")
                        
                        matched_event = message_body.get("matched_event", {})
                        if not matched_event:
                            logger.error("No matched_event field in the message body")
                            continue
                            
                        # Add sigma rule title to the event if available
                        if rule_metadata.get("title") and "sigmaRuleTitle" not in matched_event:
                            matched_event["sigmaRuleTitle"] = rule_metadata.get("title")
                        
                        # Add event source if it's missing
                        if "sigmaEventSource" not in matched_event and "eventSource" in matched_event:
                            # For CloudTrail events, use the CloudTrail source
                            matched_event["sigmaEventSource"] = "CloudTrail"
                        
                        # Process the event
                        process_event(matched_event, rule_metadata, {
                            "sns_topic": os.environ.get("SNS_TOPIC_ARN"),
                            "source_email": os.environ.get("SOURCE_EMAIL"),
                            "destination_email": os.environ.get("EMAIL_RECIPIENT"),
                            "api_key": os.environ.get("VPNAPI_KEY"),
                            "correlation_enabled": os.environ.get("CORRELATION_ENABLED", "false")
                        })
                    except Exception as e:
                        logger.error(f"Error processing SQS message: {str(e)}")
                        # Log the message body for debugging
                        try:
                            logger.error(f"Message body: {record.get('body', '{}')[:500]}...")
                        except:
                            logger.error("Could not log message body")
        
        return {"statusCode": "200", "body": "Event processed successfully"}
    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}")
        return {"statusCode": "500", "body": f"Error: {str(e)}"}

def register_plugins() -> None:
    """Register plugins with the plugin registry."""
    # Import plugins
    from plugins.cloudtrail import CloudTrailPlugin
    from plugins.generic import GenericEventPlugin
    
    # Always register CloudTrail plugin
    plugin_registry.register_plugin(CloudTrailPlugin())
    logger.info("Registered CloudTrail plugin")
    
    # Register Generic plugin (always enabled as fallback)
    plugin_registry.register_plugin(GenericEventPlugin())
    logger.info("Registered Generic plugin")
    
    # Log all registered plugins
    plugins = plugin_registry.get_all_plugins()
    logger.info(f"Registered plugins: {', '.join([p.get_plugin_name() for p in plugins])}")

def should_send_notification(severity: str, min_severity: str = None) -> bool:
    """
    Check if notification should be sent based on severity threshold.
    
    Args:
        severity: Current event/rule severity
        min_severity: Minimum severity threshold (defaults to env var or constant)
        
    Returns:
        bool: True if notification should be sent
    """
    threshold = os.environ.get("MIN_NOTIFICATION_SEVERITY", min_severity or DEFAULT_MIN_SEVERITY)
    threshold_level = SEVERITY_LEVELS.get(threshold.lower(), SEVERITY_LEVELS["medium"])
    current_level = SEVERITY_LEVELS.get(severity.lower(), SEVERITY_LEVELS["info"])
    
    should_send = current_level >= threshold_level
    
    logger.info(
        f"Severity check: Current severity '{severity}' (level {current_level}) "
        f"{'meets' if should_send else 'does not meet'} "
        f"threshold '{threshold}' (level {threshold_level})"
    )
    
    return should_send

def process_event(matched_event: Dict[str, Any], rule_metadata: Dict[str, Any], config: Dict[str, Any]) -> None:
    """
    Process a single event and send notifications if needed.
    
    Args:
        matched_event: The matched event
        rule_metadata: The Sigma rule metadata
        config: Configuration dictionary
    """
    # Find the appropriate plugin for this event
    plugin = plugin_registry.get_plugin_for_event(matched_event)
    
    if not plugin:
        logger.warning(f"No plugin found for event type: {matched_event.get('eventType', 'unknown')}")
        return
    
    logger.info(f"Using plugin '{plugin.get_plugin_name()}' for event type '{plugin.get_event_type()}'")
    
    # Check if the event should be excluded based on exception rules
    rule_title = rule_metadata.get('title', 'unknown')
    if exception_helper and exception_helper.is_excluded(rule_title, matched_event):
        logger.info(f"Event excluded by exception rule for '{rule_title}', skipping processing")
        return
    
    # Extract actor using the plugin
    actor = plugin.extract_actor(matched_event)
    
    # Get event details using the plugin
    event_details = plugin.get_event_details(matched_event)
    
    # Determine event type and process accordingly
    event_type = determine_event_type(rule_metadata)
    current_severity = rule_metadata.get('level', 'info')
    correlated_events = None
    threshold_exceeded = False
    cooldown_minutes = None
    threshold_info = None
    
    # Get global cooldown period from environment variable
    global_cooldown_minutes = int(os.environ.get("NOTIFICATION_COOLDOWN_MINUTES", "60"))
    
    # Check if DynamoDB table is available for correlation/threshold features
    if not dynamodb_table:
        logger.info("DynamoDB table not configured - correlation and threshold features disabled")
        event_type = "regular"  # Force regular event processing
    
    # Process based on event type
    if event_type == "threshold" and threshold_helper and dynamodb_table:
        logger.info(f"Processing threshold event for rule: {rule_metadata.get('title', 'unknown')}")
        # Store event as threshold type with short TTL
        dynamodb_helper.store_event(matched_event, rule_metadata, event_type="threshold")
        
        # Check if threshold is exceeded - now with threshold_info return value
        threshold_exceeded, severity_adjustment, threshold_info = threshold_helper.find_threshold_matches(
            matched_event, rule_metadata, dynamodb_table
        )
        
        if threshold_exceeded:
            logger.info(f"THRESHOLD EXCEEDED: Adjusting severity from {rule_metadata.get('level', 'info')} to {severity_adjustment}")
            current_severity = severity_adjustment
            rule_metadata['level'] = severity_adjustment
            
            # Get cooldown period from threshold rule if specified, otherwise use global cooldown
            for threshold_rule in threshold_helper.threshold_rules_cache:
                if threshold_rule.get('sigmaRuleTitle') == rule_metadata.get('title'):
                    cooldown_minutes = threshold_rule.get('cooldownMinutes', global_cooldown_minutes)
                    logger.info(f"Using rule-specific cooldown period of {cooldown_minutes} minutes for threshold rule '{rule_metadata.get('title')}'")
                    break
            
            if cooldown_minutes is None:
                cooldown_minutes = global_cooldown_minutes
                logger.info(f"Using global cooldown period of {cooldown_minutes} minutes for threshold rule '{rule_metadata.get('title')}'")
            
            # Log threshold information for debugging
            if threshold_info:
                logger.info(f"Using threshold info for notification: {threshold_info}")
            else:
                logger.warning("Threshold was exceeded but no threshold info was generated")
            
            # Store as a regular event for long-term storage
            dynamodb_helper.store_event(matched_event, rule_metadata, event_type="regular")
        else:
            logger.info(f"Threshold not exceeded for rule: {rule_metadata.get('title', 'unknown')}, keeping original severity: {rule_metadata.get('level', 'info')}")
    
    elif event_type == "correlation" and config.get("correlation_enabled") == "true" and correlation_helper and dynamodb_table:
        logger.info(f"Processing correlation event for rule: {rule_metadata.get('title', 'unknown')}")
        # Store event as correlation type
        dynamodb_helper.store_event(matched_event, rule_metadata, event_type="correlation")
        
        # Check for correlation matches
        matches = correlation_helper.find_correlations(matched_event, rule_metadata, dynamodb_table)
        if matches:
            highest_severity_match = max(
                matches,
                key=lambda x: SEVERITY_LEVELS.get(x['severity_adjustment'], 0)
            )
            current_severity = highest_severity_match['severity_adjustment']
            correlated_events = highest_severity_match['correlated_events']
            logger.info(f"CORRELATION FOUND: Adjusting severity from {rule_metadata.get('level', 'info')} to: {current_severity}")
            rule_metadata['level'] = current_severity
            
            # Use global cooldown for correlation events
            cooldown_minutes = global_cooldown_minutes
            logger.info(f"Using global cooldown period of {cooldown_minutes} minutes for correlation rule '{rule_metadata.get('title')}'")
            
            # Store as a regular event for long-term storage
            dynamodb_helper.store_event(matched_event, rule_metadata, event_type="regular")
        else:
            logger.info(f"No correlation found for rule: {rule_metadata.get('title', 'unknown')}, keeping original severity: {rule_metadata.get('level', 'info')}")
    
    else:
        # Regular event processing
        logger.info(f"Processing regular event for rule: {rule_metadata.get('title', 'unknown')}")
        if dynamodb_helper:
            dynamodb_helper.store_event(matched_event, rule_metadata, event_type="regular")
        else:
            logger.info("DynamoDB table not configured - skipping event storage")
        
        # Use global cooldown for regular events
        cooldown_minutes = global_cooldown_minutes
        logger.info(f"Using global cooldown period of {cooldown_minutes} minutes for regular rule '{rule_metadata.get('title')}'")

    # Only send notifications if severity meets threshold or if threshold was exceeded
    min_severity = os.environ.get("MIN_NOTIFICATION_SEVERITY", DEFAULT_MIN_SEVERITY)
    should_notify = should_send_notification(current_severity) or threshold_exceeded
    
    # Initialize notification helper if DynamoDB is available
    notification_helper = NotificationHelper(dynamodb_table) if dynamodb_table else None
    
    # Check cooldown period if applicable and DynamoDB is available
    cooldown_applied = False
    if should_notify and cooldown_minutes is not None and notification_helper:
        rule_title = rule_metadata.get('title', 'unknown')
        should_notify = notification_helper.should_send_notification(rule_title, cooldown_minutes)
        
        if not should_notify:
            # The notification was skipped due to cooldown
            cooldown_applied = True
            
        if should_notify:
            # Update the last notification time
            notification_helper.update_notification_time(rule_title)
    elif should_notify and not notification_helper:
        logger.info("DynamoDB table not configured - cooldown tracking disabled, always sending notifications")
    
    if should_notify:
        logger.info(f"SENDING NOTIFICATION: Severity {current_severity} meets or exceeds threshold {min_severity} or threshold was exceeded")
        send_notifications(matched_event, rule_metadata, config, correlated_events, threshold_info)
    else:
        if cooldown_applied:
            logger.info(f"SKIPPING NOTIFICATION: In cooldown period (notification threshold was met but cooldown period is active)")
        else:
            logger.info(f"SKIPPING NOTIFICATION: Severity {current_severity} below threshold {min_severity} and threshold was not exceeded")

def determine_event_type(rule_metadata: Dict[str, Any]) -> str:
    """
    Determine the event type based on rule metadata.
    
    Args:
        rule_metadata: The Sigma rule metadata
        
    Returns:
        str: Event type (threshold, correlation, or regular)
    """
    rule_title = rule_metadata.get('title', '')
    
    # Check if it's a threshold rule
    if threshold_helper and threshold_helper.has_matching_rule(rule_title):
        return "threshold"
    
    # Check if it's a correlation rule
    if correlation_helper and correlation_helper.has_matching_rule(rule_title):
        return "correlation"
    
    # Default to regular
    return "regular"

def send_notifications(matched_event: Dict[str, Any], rule_metadata: Dict[str, Any], 
                      config: Dict[str, Any], correlated_events: List[Dict[str, Any]] = None,
                      threshold_info: Dict[str, Any] = None) -> None:
    """
    Send notifications using either SNS or SES based on configuration.
    
    Args:
        matched_event: The matched event
        rule_metadata: The Sigma rule metadata
        config: Configuration dictionary
        correlated_events: Optional list of correlated events
        threshold_info: Optional dictionary containing threshold information
    """
    # Find the appropriate plugin
    plugin = plugin_registry.get_plugin_for_event(matched_event)
    
    if not plugin:
        logger.warning(f"No plugin found for event type: {matched_event.get('eventType', 'unknown')}")
        return
    
    # Debug logging to trace threshold information
    logger.info(f"DEBUG: Received threshold_info in send_notifications: {threshold_info}")
    
    if config.get("sns_topic"):
        logger.info("Sending notification via SNS")
        sns_send_email(config["sns_topic"], matched_event, correlated_events, threshold_info, rule_metadata)
    elif config.get("source_email") and config.get("destination_email"):
        sections = []
        
        # Add Sigma rule information first
        logger.info("Generating Sigma rule section")
        sigma_info = generate_sigma_rule_section(rule_metadata)
        sections.append(sigma_info)
        
        # Add event information section using the plugin
        logger.info(f"Generating event info section using plugin '{plugin.get_plugin_name()}'")
        event_section = plugin.generate_event_section(matched_event)
        sections.append(event_section)

        # Add CloudTrail Information section if it's a CloudTrail event
        if matched_event.get("sigmaEventSource") == "CloudTrail":
            logger.info("Adding CloudTrail Information section")
            cloudtrail_section = generate_cloudtrail_information_section(matched_event)
            sections.append(cloudtrail_section)

        # Add correlation section if available
        if correlated_events:
            logger.info("Adding correlation information to notification")
            correlation_info = generate_correlation_section(correlated_events)
            sections.append(correlation_info)
            
        # Add threshold section if available
        if threshold_info:
            logger.info(f"Adding threshold information to notification: {threshold_info}")
            threshold_section = generate_threshold_section(threshold_info)
            logger.info(f"Generated threshold section: {threshold_section[:100]}...")
            sections.append(threshold_section)

        # Only add IP info section if API key is available and event has sourceIPAddress
        api_key = config.get("api_key")
        if api_key and matched_event and matched_event.get('sourceIPAddress'):
            try:
                logger.info("Generating IP info section")
                ip_info, _ = get_ip_information_section(matched_event, api_key)
                if ip_info:  # Only add if we got meaningful info
                    sections.append(ip_info)
            except Exception as e:
                logger.error(f"Error generating IP information section: {str(e)}")
                # Continue without IP info if there's an error

        logger.info("Generating HTML email")
        email_html = generate_email_html(generate_style(), sections)

        ses_send_email(
            email_html, 
            matched_event, 
            config["source_email"], 
            config["destination_email"],
            rule_metadata,
            correlated_events,
            threshold_info
        )
    else:
        logger.warning("No notification method configured - skipping notifications")