"""
CloudTrail plugin for the Sigma Event Processor.
This plugin handles CloudTrail events.
"""
import html
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from urllib.parse import quote

from plugins.base import EventSourcePlugin
from utils import get_nested_value
from cloudtrail_helpers import generate_cloudtrail_information_section, generate_cloudtrail_link

logger = logging.getLogger()

class CloudTrailPlugin(EventSourcePlugin):
    """Plugin for processing CloudTrail events."""
    
    def get_plugin_name(self) -> str:
        """
        Return the name of the plugin.
        
        Returns:
            str: The name of the plugin
        """
        return "cloudtrail"
    
    def get_event_type(self) -> str:
        """
        Return the event type this plugin handles.
        
        Returns:
            str: The event type
        """
        return "CloudTrail"
    
    def can_process_event(self, event: Dict[str, Any]) -> bool:
        """
        Determine if this plugin can process the given event.
        
        Args:
            event: The event to check
            
        Returns:
            bool: True if this plugin can process the event, False otherwise
        """
        # Check for sigmaEventSource field added by the CloudTrail analyzer
        return event.get("sigmaEventSource") == "CloudTrail"
    
    def extract_actor(self, event: Dict[str, Any]) -> str:
        """
        Extract the actor from the event.
        
        Args:
            event: The event to extract the actor from
            
        Returns:
            str: The actor (IAM ARN)
        """
        # Try to get the actor from the event
        actor = event.get('actor', '')
        
        # If no actor is set, try to extract it from the event
        if not actor:
            # For CloudTrail events, the actor is typically in the userIdentity field
            user_identity = event.get('userIdentity', {})
            
            # Try different fields in order of preference
            if user_identity.get('type') == 'IAMUser':
                actor = user_identity.get('userName', '')
            elif user_identity.get('type') == 'AssumedRole':
                actor = user_identity.get('arn', '')
            elif user_identity.get('type') == 'Root':
                actor = 'root'
            elif user_identity.get('type') == 'AWSService':
                actor = user_identity.get('invokedBy', '')
            else:
                # Fallback to the ARN if available
                actor = user_identity.get('arn', '')
        
        return actor
    
    def generate_event_section(self, event: Dict[str, Any]) -> str:
        """
        Generate HTML section for the event.
        
        Args:
            event: The event to generate the section for
            
        Returns:
            str: HTML section for the event
        """
        # Extract and escape event details
        event_type = html.escape(str(event.get('eventType', 'unknown')))
        actor = html.escape(str(self.extract_actor(event)))
        source_ip = html.escape(str(event.get('sourceIPAddress', 'unknown')))
        timestamp = html.escape(str(event.get('eventTime', 'unknown')))
        region = html.escape(str(event.get('awsRegion', 'unknown')))
        account_id = html.escape(str(event.get('recipientAccountId', 'unknown')))
        event_name = html.escape(str(event.get('eventName', 'unknown')))
        event_source = html.escape(str(event.get('eventSource', 'unknown')))
        
        # Generate HTML section
        section = f"""
        <div class='section'>
            <div class='section-title'>Event Information</div>
            <div>Event Type: <span class='value'>{event_type}</span></div>
            <div>Event Name: <span class='value'>{event_name}</span></div>
            <div>Event Source: <span class='value'>{event_source}</span></div>
            <div>Actor: <span class='value'>{actor}</span></div>
            <div>Source IP: <span class='value'>{source_ip}</span></div>
            <div>Timestamp: <span class='value'>{timestamp}</span></div>
            <div>Region: <span class='value'>{region}</span></div>
            <div>Account ID: <span class='value'>{account_id}</span></div>
        </div>
        """
        
        return section
    
    def get_event_details(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract relevant details from the event for storage and processing.
        
        Args:
            event: The event to extract details from
            
        Returns:
            Dict[str, Any]: Dictionary of event details
        """
        # Safety check for None values
        if event is None:
            logger.warning("None event provided to get_event_details")
            return {
                "eventType": "unknown",
                "actor": "unknown",
                "sourceIPAddress": "unknown",
                "eventName": "unknown",
                "target": "unknown",
                "accountId": "unknown",
                "region": "unknown",
                "eventTime": "unknown"
            }
            
        # Extract user identity with safety checks
        user_identity = event.get("userIdentity", {}) or {}
        request_parameters = event.get("requestParameters", {}) or {}
        response_elements = event.get("responseElements", {}) or {}
        
        details = {
            "eventType": event.get("eventType", "unknown"),
            "actor": self.extract_actor(event),
            "sourceIPAddress": event.get("sourceIPAddress", "unknown"),
            "eventName": event.get("eventName", "unknown"),
            "target": request_parameters.get("roleName", "unknown"),
            "accountId": event.get("recipientAccountId", "unknown"),
            "region": event.get("awsRegion", "unknown"),
            "eventTime": event.get("eventTime", "unknown"),
            "userIdentityType": user_identity.get("type", "unknown"),
            "userIdentityPrincipalId": user_identity.get("principalId", "unknown"),
            "userIdentityAccountId": user_identity.get("accountId", "unknown"),
            "userIdentityAccessKeyId": user_identity.get("accessKeyId", "unknown"),
            "eventSource": event.get("eventSource", "unknown"),
            "resources": event.get("resources", []) or [],
            "userAgent": event.get("userAgent", "unknown"),
            "requestParameters": request_parameters,
            "responseElements": response_elements,
            "errorCode": event.get("errorCode", "unknown"),
            "errorMessage": event.get("errorMessage", "unknown")
        }
        
        # Add CloudTrail console link if available
        if event.get("eventName") and event.get("eventTime"):
            try:
                details["cloudtrailLink"] = generate_cloudtrail_link(event)
            except Exception as e:
                logger.error(f"Error generating CloudTrail link: {str(e)}")
                details["cloudtrailLink"] = ""
        
        return details
    
    def generate_cloudtrail_link(self, event: Dict[str, Any], window_minutes: int = 20) -> str:
        """
        Generates a CloudTrail console link for the event with a time window.
        
        Args:
            event: The CloudTrail event
            window_minutes: Time window in minutes (default 20)
            
        Returns:
            str: CloudTrail console URL
        """
        try:
            # Parse the event time
            event_time = datetime.fromisoformat(event.get('eventTime', '').replace('Z', '+00:00'))
            
            # Calculate start and end times (window_minutes/2 before and after the event)
            half_window = timedelta(minutes=window_minutes/2)
            start_time = event_time - half_window
            end_time = event_time + half_window
            
            # Format times for URL - use ISO format with milliseconds
            start_str = start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_str = end_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            # Get event name and region
            event_name = event.get('eventName', '')
            region = event.get('awsRegion', 'us-east-1')  # Default to us-east-1 if not specified
            
            # Build the URL with proper formatting
            # The correct format for CloudTrail console URL is:
            # https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/events?EventName={eventName}&StartTime={startTime}&EndTime={endTime}
            base_url = f"https://{region}.console.aws.amazon.com/cloudtrail/home"
            params = f"region={region}#/events?EventName={quote(event_name)}&StartTime={start_str}&EndTime={end_str}"
            
            return f"{base_url}?{params}"
        except Exception as e:
            logger.error(f"Failed to generate CloudTrail link: {str(e)}")
            return ""
    
    def generate_cloudtrail_information_section(self, event: Dict[str, Any]) -> str:
        """
        Generates HTML section with CloudTrail information.
        
        Args:
            event: The CloudTrail event data
            
        Returns:
            str: HTML formatted section with CloudTrail information
        """
        def add_section(label, *keys):
            """Adds a section to the HTML output if the specified keys exist in the finding."""
            value = get_nested_value(event, keys)

            if value is not None:
                safe_value = html.escape(str(value))
                sections.append(
                    f"<div>{label}: <span class='value'>{safe_value}</span></div>"
                )
            else:
                logger.debug(f"Missing CloudTrail key: {' -> '.join(keys)}")

        sections = []

        # Standard sections
        add_section("User Identity type", "userIdentity", "type")
        add_section("User Identity Principal ID", "userIdentity", "principalId")
        add_section("User Identity ARN", "userIdentity", "arn")
        add_section("User Identity account", "userIdentity", "accountId")
        add_section("User Identity accessKeyId", "userIdentity", "accessKeyId")
        add_section("Event Time", "eventTime")
        add_section("AWS Account", "recipientAccountId")
        add_section("Region", "awsRegion")
        add_section("Event", "eventName")
        add_section("Source", "eventSource")
        add_section("Resources", "resources")

        # Generate CloudTrail console link and add it at the end
        cloudtrail_link = self.generate_cloudtrail_link(event)
        if cloudtrail_link:
            sections.append(
                f"""<div class="cloudtrail-link">
                    <a href="{cloudtrail_link}" target="_blank" class="console-button">
                        View in CloudTrail Console
                    </a>
                </div>"""
            )

        sections_html = f"""
            <div class="section">
                <div class="section-title">CloudTrail Information</div>
                {"".join(sections)}
            </div>
            """
        return sections_html