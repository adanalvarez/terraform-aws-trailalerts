import html
from utils import get_nested_value
import logging
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from urllib.parse import quote
import json

# Constants for HTML templates
HTML_TEMPLATES = {
    "section": """
        <div class="section">
            <div class="section-title">{title}</div>
            {content}
        </div>
        """,
    "field": "<div>{label}: <span class='value'>{value}</span></div>",
    "link_button": """
            <div class="cloudtrail-link">
                <a href="{url}" target="_blank" class="console-button">
                    {text}
                </a>
            </div>"""
}

# Common resource identifier fields in CloudTrail events
RESOURCE_ID_FIELDS = [
    'instanceId', 'bucketName', 'roleName', 'userName', 'groupName', 'policyName',
    'trailName', 'functionName', 'tableId', 'clusterId', 'resourceArn', 'resourceId',
    'databaseName', 'keyId', 'certificateId', 'directoryId'
]


def validate_cloudtrail_event(event: Dict[str, Any]) -> bool:
    """
    Validates that a dictionary contains the minimum required fields to be a CloudTrail event.
    
    Args:
        event: The potential CloudTrail event
        
    Returns:
        bool: True if event appears to be a valid CloudTrail event
    """
    # Check for minimum required CloudTrail event fields
    required_fields = ['eventTime', 'eventName', 'awsRegion']
    
    return all(field in event for field in required_fields)


def format_iso_time(dt: datetime) -> str:
    """
    Format a datetime object to AWS CloudTrail console URL compatible ISO format.
    
    Args:
        dt: The datetime to format
        
    Returns:
        str: Formatted datetime string
    """
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')


def generate_cloudtrail_link(event: Dict[str, Any], window_minutes: int = 20) -> str:
    """
    Generates a CloudTrail console link for the event with a time window.
    
    Args:
        event: The CloudTrail event
        window_minutes: Time window in minutes (default 20)
        
    Returns:
        str: CloudTrail console URL
    """
    # Validate input
    if not validate_cloudtrail_event(event):
        logging.warning("Invalid CloudTrail event provided to generate_cloudtrail_link")
        return ""
        
    try:
        # Parse the event time
        try:
            event_time_str = event.get('eventTime', '')
            if not event_time_str:
                raise ValueError("Event time is missing or empty")
                
            event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
        except ValueError as e:
            logging.error(f"Failed to parse event time: {str(e)}")
            # If we can't parse the time, use current time as fallback
            event_time = datetime.utcnow()
        
        # Calculate start and end times (window_minutes/2 before and after the event)
        half_window = timedelta(minutes=window_minutes/2)
        start_time = event_time - half_window
        end_time = event_time + half_window
        
        # Format times for URL
        start_str = format_iso_time(start_time)
        end_str = format_iso_time(end_time)
        
        # Get event name and region
        event_name = event.get('eventName', '')
        region = event.get('awsRegion', 'us-east-1')  # Default to us-east-1 if not specified
        
        # Build URL parameters
        url_params = [
            f"region={region}#/events?EventName={quote(event_name)}",
            f"StartTime={start_str}",
            f"EndTime={end_str}"
        ]
               
        # Build the URL
        base_url = f"https://{region}.console.aws.amazon.com/cloudtrail/home"
        params = "&".join(url_params)
        
        return f"{base_url}?{params}"
    except Exception as e:
        logging.error(f"Failed to generate CloudTrail link: {str(e)}")
        return ""


def escape_html_value(value: Any) -> str:
    """
    Safely escapes any value for HTML output.
    
    Args:
        value: Any value to be escaped
        
    Returns:
        str: HTML escaped string
    """
    return html.escape(str(value))


def create_html_section(label: str, value: Any) -> str:
    """
    Creates an HTML section with a label and value.
    
    Args:
        label: The label for the section
        value: The value to display
        
    Returns:
        str: HTML formatted section
    """
    if value is not None:
        safe_value = escape_html_value(value)
        return HTML_TEMPLATES["field"].format(label=label, value=safe_value)
    return ""


def format_resource_dict(resource: Dict[str, Any]) -> str:
    """
    Format a resource dictionary into HTML.
    
    Args:
        resource: Dictionary containing resource information
        
    Returns:
        str: HTML formatted resource
    """
    resource_html = "<div class='resource-item'>"
    
    # Display the resource type first if available
    if 'resourceType' in resource:
        resource_html += f"<div class='resource-type'>{escape_html_value(resource['resourceType'])}</div>"
    
    # Add ARN as it's a unique identifier
    if 'ARN' in resource:
        resource_html += f"<div class='resource-arn'>ARN: <span class='highlight'>{escape_html_value(resource['ARN'])}</span></div>"
    
    # Add resource name
    if 'resourceName' in resource:
        resource_html += f"<div class='resource-name'>Name: <span class='emphasis'>{escape_html_value(resource['resourceName'])}</span></div>"
    
    # Add standard fields that might be present
    standard_fields = ['accountId', 'resourceOwner', 'resourceRole', 'resourceTag']
    for field in standard_fields:
        if field in resource:
            resource_html += f"<div class='resource-detail'>{field}: {escape_html_value(resource[field])}</div>"
    
    # Add any remaining fields
    skip_fields = ['ARN', 'resourceName', 'resourceType'] + standard_fields
    for key, value in resource.items():
        if key not in skip_fields:
            resource_html += f"<div class='resource-detail'>{key}: {escape_html_value(value)}</div>"
    
    resource_html += "</div>"
    return resource_html


def extract_resource_from_parameters(event: Dict[str, Any]) -> Optional[str]:
    """
    Extract resource identifier from request or response parameters.
    
    Args:
        event: The CloudTrail event
        
    Returns:
        Optional[str]: HTML formatted resource or None if not found
    """
    # Check request parameters first
    request_params = get_nested_value(event, ["requestParameters"])
    if isinstance(request_params, dict) and request_params:
        for field in RESOURCE_ID_FIELDS:
            if field in request_params:
                return f"{field}: <span class='emphasis'>{escape_html_value(request_params[field])}</span>"
    
    # Then check response elements
    response_elems = get_nested_value(event, ["responseElements"])
    if isinstance(response_elems, dict) and response_elems:
        for key, value in response_elems.items():
            if value and key.lower().endswith(('id', 'arn', 'name')):
                return f"{key}: <span class='emphasis'>{escape_html_value(value)}</span>"
    
    return None


def format_resources_list(resources: List[Any]) -> str:
    """
    Format a list of resources into HTML.
    
    Args:
        resources: List of resource objects
        
    Returns:
        str: HTML formatted resources list
    """
    resources_html = "<ul class='resources-list'>"
    
    for resource in resources:
        if isinstance(resource, dict):
            resource_html = format_resource_dict(resource)
            resources_html += f"<li>{resource_html}</li>"
        else:
            # If not a dict, just convert to string
            resources_html += f"<li><div class='resource-item'>{escape_html_value(resource)}</div></li>"
    
    resources_html += "</ul>"
    return resources_html


def generate_cloudtrail_information_section(event: Dict[str, Any]) -> str:
    """
    Generates HTML section with CloudTrail information.
    
    Args:
        event: The CloudTrail event data
        
    Returns:
        str: HTML formatted section with CloudTrail information
    """
    if not validate_cloudtrail_event(event):
        logging.warning("Invalid CloudTrail event provided to generate_cloudtrail_information_section")
        return "<div class='section'><div class='section-title'>CloudTrail Information</div><div>Invalid CloudTrail event data</div></div>"

    sections = []

    # User identity sections
    user_identity_fields = [
        ("User Identity type", "userIdentity", "type"),
        ("User Identity Principal ID", "userIdentity", "principalId"),
        ("User Identity ARN", "userIdentity", "arn"),
        ("User Identity account", "userIdentity", "accountId"),
        ("User Identity accessKeyId", "userIdentity", "accessKeyId"),
        ("User Identity userName", "userIdentity", "userName"),
    ]
    
    for label, *keys in user_identity_fields:
        value = get_nested_value(event, keys)
        if value is not None:
            sections.append(create_html_section(label, value))
        else:
            logging.debug(f"Missing CloudTrail key: {' -> '.join(keys)}")
    
    # Event metadata sections
    event_fields = [
        ("Event Time", "eventTime"),
        ("AWS Account", "recipientAccountId"),
        ("Region", "awsRegion"),
        ("Event", "eventName"),
        ("Source", "eventSource"),
        ("Event ID", "eventID"),
        ("Event Type", "eventType"),
        ("API Version", "apiVersion"),
    ]
    
    for label, *keys in event_fields:
        value = get_nested_value(event, keys)
        if value is not None:
            sections.append(create_html_section(label, value))
    
    # Resources section
    resources = get_nested_value(event, ["resources"])
    if resources and isinstance(resources, list) and resources:
        resources_html = format_resources_list(resources)
        sections.append(f"<div>Resources: {resources_html}</div>")
    else:
        # Try to find other resource identifiers in the event
        target_resource = extract_resource_from_parameters(event)
        if target_resource:
            sections.append(f"<div>Resource: <div class='inferred-resource'>{target_resource}</div></div>")
        else:
            logging.debug("No resources found in CloudTrail event")

    # Additional error related information if available
    error_code = get_nested_value(event, ["errorCode"])
    error_message = get_nested_value(event, ["errorMessage"])
    
    if error_code or error_message:
        if error_code:
            sections.append(create_html_section("Error Code", error_code))
        if error_message:
            sections.append(create_html_section("Error Message", error_message))

    # Generate CloudTrail console link
    cloudtrail_link = generate_cloudtrail_link(event)
    if cloudtrail_link:
        sections.append(
            HTML_TEMPLATES["link_button"].format(
                url=cloudtrail_link,
                text="View in CloudTrail Console"
            )
        )

    # Final assembly
    sections_html = HTML_TEMPLATES["section"].format(
        title="CloudTrail Information",
        content="".join(sections)
    )
    return sections_html
