"""
Generic event plugin for the Sigma Event Processor.
This plugin handles events that don't match any other plugin.
"""
import html
import json
import logging
from typing import Dict, Any

from plugins.base import EventSourcePlugin

logger = logging.getLogger()

class GenericEventPlugin(EventSourcePlugin):
    """Plugin for processing generic events."""
    
    def get_plugin_name(self) -> str:
        """Get the name of the plugin."""
        return "generic"
    
    def get_event_type(self) -> str:
        """Get the event type this plugin handles."""
        return "Generic"
    
    def can_process_event(self, event: Dict[str, Any]) -> bool:
        """
        Check if this plugin can process the given event.
        
        Args:
            event: The event to check
            
        Returns:
            bool: True if this plugin can process the event
        """
        # This plugin can process any event that doesn't match other plugins
        return True
    
    def extract_actor(self, event: Dict[str, Any]) -> str:
        """
        Extract the actor from a generic event.
        
        Args:
            event: The event
            
        Returns:
            str: The actor identifier
        """
        # Try to get the actor from the event
        actor = event.get('actor', '')
        
        # If no actor is set, try to extract it from common fields
        if not actor:
            # Try different fields in order of preference
            actor = (
                event.get('userIdentity', {}).get('arn', '') or
                event.get('userIdentity', {}).get('userName', '') or
                event.get('userIdentity', {}).get('type', '') or
                event.get('sourceIPAddress', '') or
                event.get('source', '') or
                'unknown'
            )
        
        return actor
    
    def generate_event_section(self, event: Dict[str, Any]) -> str:
        """
        Generate an HTML section for a generic event.
        
        Args:
            event: The event
            
        Returns:
            str: HTML section for the event
        """
        # Extract event details
        event_type = event.get('eventType', 'unknown')
        actor = self.extract_actor(event)
        source_ip = event.get('sourceIPAddress', 'unknown')
        timestamp = event.get('eventTime', 'unknown')
        region = event.get('awsRegion', 'unknown')
        account_id = event.get('recipientAccountId', 'unknown')
        
        # Generate HTML section
        html = f"""
        <div class='section'>
            <div class='section-title'>Event Information</div>
            <div>Event Type: <span class='value'>{event_type}</span></div>
            <div>Actor: <span class='value'>{actor}</span></div>
            <div>Source IP: <span class='value'>{source_ip}</span></div>
            <div>Timestamp: <span class='value'>{timestamp}</span></div>
            <div>Region: <span class='value'>{region}</span></div>
            <div>Account ID: <span class='value'>{account_id}</span></div>
        </div>
        """
        
        return html
    
    def get_event_details(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract relevant details from a generic event.
        
        Args:
            event: The event
            
        Returns:
            Dict[str, Any]: Dictionary containing event details
        """
        details = {
            'eventType': event.get('eventType', 'unknown'),
            'actor': self.extract_actor(event),
            'sourceIPAddress': event.get('sourceIPAddress', 'unknown'),
            'eventTime': event.get('eventTime', 'unknown'),
            'awsRegion': event.get('awsRegion', 'unknown'),
            'recipientAccountId': event.get('recipientAccountId', 'unknown'),
            'userAgent': event.get('userAgent', 'unknown'),
            'requestParameters': event.get('requestParameters', {}),
            'responseElements': event.get('responseElements', {}),
            'errorCode': event.get('errorCode', 'unknown'),
            'errorMessage': event.get('errorMessage', 'unknown')
        }
        
        return details 