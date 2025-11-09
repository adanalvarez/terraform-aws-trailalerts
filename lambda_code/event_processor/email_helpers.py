import boto3
from botocore.exceptions import ClientError
import logging
import os
from typing import List, Dict, Any


def generate_email_html(style: str, sections: List[str]) -> str:
    """
    Generates an HTML email template with CloudTrail information, IP information, and CloudTrail information.
    
    Args:
        style: CSS styles as string
        sections: List of HTML sections to include
        
    Returns:
        str: Complete HTML email template
    """
    try:
        # Filter out None or empty sections and join them
        valid_sections = [section for section in sections if section]
        combined_sections = "".join(valid_sections)
        
        html_template = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>CloudTrail Alert</title>
                {style}
            </head>
            <body>
            <div class="container">
                <div class="header">CloudTrail Alert</div>
                {combined_sections}
            </div>
            </body>
            </html>
        """
        return html_template
    except Exception as e:
        logging.error(f"Failed to generate HTML email: {str(e)}")
        # Return a simple fallback template
        return f"""
            <!DOCTYPE html>
            <html>
            <body>
                <h1>CloudTrail Alert</h1>
                <p>Error generating formatted email. Please check the logs.</p>
                <pre>{str(e)}</pre>
            </body>
            </html>
        """


def generate_correlation_section(correlated_events: List[Dict[str, Any]]) -> str:
    """
    Generates HTML section with correlation information.
    
    Args:
        correlated_events: List of correlated events
        
    Returns:
        str: HTML formatted correlation section
    """
    if not correlated_events:
        return ""

    events_html = []
    for event in correlated_events:
        event_html = f"""
            <div class="correlated-event">
                <div>Rule: <span class="value">{event.get('sigmaRuleTitle', 'N/A')}</span></div>
                <div>Time: <span class="value">{event.get('timestamp', 'N/A')}</span></div>
                <div>Actor: <span class="value">{event.get('actor', 'N/A')}</span></div>
                <div>Target: <span class="value">{event.get('target', 'N/A')}</span></div>
            </div>
        """
        events_html.append(event_html)

    return f"""
        <div class="section">
            <div class="section-title">Correlated Events</div>
            <div class="correlation-warning">⚠️ This alert was escalated due to correlation with previous events</div>
            {"".join(events_html)}
        </div>
    """


def generate_threshold_section(threshold_info: Dict[str, Any]) -> str:
    """
    Generates HTML section with threshold information.
    
    Args:
        threshold_info: Dictionary containing threshold information
        
    Returns:
        str: HTML formatted threshold section
    """
    if not threshold_info:
        return ""
    
    # Extract threshold information
    event_count = threshold_info.get('eventCount', threshold_info.get('event_count', 0))
    threshold_count = threshold_info.get('thresholdCount', threshold_info.get('threshold_count', 0))
    window_minutes = threshold_info.get('windowMinutes', threshold_info.get('window_minutes', 0))
    actor = threshold_info.get('actor', 'N/A')
    rule_title = threshold_info.get('ruleTitle', threshold_info.get('rule_title', 'N/A'))
    
    # Generate the threshold section
    return f"""
        <div class="section">
            <div class="section-title">Threshold Exceeded</div>
            <div class="threshold-warning">⚠️ This alert was escalated due to multiple occurrences of the same event</div>
            <div class="threshold-details">
                <div>Rule: <span class="value">{rule_title}</span></div>
                <div>Actor: <span class="value">{actor}</span></div>
                <div>Event Count: <span class="value">{event_count}</span></div>
                <div>Threshold: <span class="value">{threshold_count}</span></div>
                <div>Time Window: <span class="value">{window_minutes} minutes</span></div>
            </div>
        </div>
    """


def generate_sigma_rule_section(rule: Dict[str, Any]) -> str:
    """
    Generates HTML section with Sigma rule information.
    
    Args:
        rule: The Sigma rule metadata
        
    Returns:
        str: HTML formatted section with rule information
    """
    sections = []
    
    # Add rule information
    if rule.get("title"):
        sections.append(f"<div>Title: <span class='value'>{rule['title']}</span></div>")
    if rule.get("id"):
        sections.append(f"<div>Rule ID: <span class='value'>{rule['id']}</span></div>")
    if rule.get("level"):
        severity_class = f"severity-{rule['level'].lower()}"
        sections.append(f"<div>Severity: <span class='value {severity_class}'>{rule['level'].upper()}</span></div>")
    if rule.get("description"):
        sections.append(f"<div>Description: <span class='value'>{rule['description']}</span></div>")
    if rule.get("author"):
        sections.append(f"<div>Author: <span class='value'>{rule['author']}</span></div>")
    if rule.get("references"):
        refs = "</li><li>".join(rule['references'])
        sections.append(f"<div>References: <ul><li>{refs}</li></ul></div>")

    return f"""
        <div class="section">
            <div class="section-title">Sigma Rule Information</div>
            {"".join(sections)}
        </div>
    """


def ses_send_email(html_content: str, event: Dict[str, Any], source_email: str, 
                  destination_email: str, rule: Dict[str, Any],
                  correlated_events: List[Dict[str, Any]] = None,
                  threshold_info: Dict[str, Any] = None) -> None:
    """
    Sends an email using AWS SES.
    
    Args:
        html_content: HTML content of the email
        event: The CloudTrail event
        source_email: Source email address
        destination_email: Destination email address
        rule: The Sigma rule that triggered the alert
        correlated_events: Optional list of correlated events
        threshold_info: Optional threshold information
    """
    ses_client = boto3.client("ses")
    rule_title = rule.get("title", "Unknown Rule")
    severity = rule.get("level", "unknown").upper()
    
    # Add severity indicator to subject with TRAILALERTS prefix
    subject = f"[TRAILALERTS][{severity}] {rule_title}"
    
    # Add correlation or threshold indicator to subject
    if correlated_events:
        subject = f"[CORRELATED] {subject}"
    if threshold_info:
        subject = f"[THRESHOLD EXCEEDED] {subject}"

    try:
        response = ses_client.send_email(
            Source=source_email,
            Destination={"ToAddresses": [destination_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Html": {"Data": html_content}},
            },
        )
        logging.info(f"Email sent: {response['MessageId']}")
    except ClientError as e:
        logging.error(f"Failed to send email: {str(e)}")

def sns_send_email(sns_topic: str, records: Dict[str, Any], 
                  correlated_events: List[Dict[str, Any]] = None,
                  threshold_info: Dict[str, Any] = None,
                  rule_metadata: Dict[str, Any] = None) -> None:
    """
    Sends a message to an SNS topic.
    
    Args:
        sns_topic: The SNS topic ARN
        records: The CloudTrail event records
        correlated_events: Optional list of correlated events
        threshold_info: Optional dictionary containing threshold information
        rule_metadata: Optional rule metadata containing severity information
    """
    sns_client = boto3.client("sns")
    
    # Get severity from rule metadata
    severity = "UNKNOWN"
    if rule_metadata and "level" in rule_metadata:
        severity = rule_metadata["level"].upper()
    
    # Basic event information with severity
    message = f'SEVERITY: {severity}\n'
    message += f'Event: {records.get("eventName", "N/A")}\n'
    message += f'Event Source: {records.get("eventSource", "N/A")}\n'
    message += f'Principal ID: {records.get("userIdentity", {}).get("principalId", "N/A")}\n'
    message += f'Account ID: {records.get("userIdentity", {}).get("accountId", "N/A")}\n'
    message += f'AWS Region: {records.get("awsRegion", "N/A")}\n'
    message += f'Source IP Address: {records.get("sourceIPAddress", "N/A")}\n'
    message += f'Request Parameters: {records.get("requestParameters", "N/A")}\n'

    # Add correlation information if available
    if correlated_events:
        message += "\nCORRELATED EVENTS:\n"
        message += "⚠️ This alert was escalated due to correlation with previous events\n\n"
        for event in correlated_events:
            message += f'Related Rule: {event.get("sigmaRuleTitle", "N/A")}\n'
            message += f'Time: {event.get("timestamp", "N/A")}\n'
            message += f'Actor: {event.get("actor", "N/A")}\n'
            message += f'Target: {event.get("target", "N/A")}\n'
            message += '-' * 40 + '\n'
    
    # Add threshold information if available
    if threshold_info:
        message += "\nTHRESHOLD EXCEEDED:\n"
        message += "⚠️ This alert was escalated due to multiple occurrences of the same event\n\n"
        event_count = threshold_info.get('eventCount', threshold_info.get('event_count', 0))
        threshold_count = threshold_info.get('thresholdCount', threshold_info.get('threshold_count', 0))
        window_minutes = threshold_info.get('windowMinutes', threshold_info.get('window_minutes', 0))
        actor = threshold_info.get('actor', 'N/A')
        rule_title = threshold_info.get('ruleTitle', threshold_info.get('rule_title', 'N/A'))
        
        message += f'Rule: {rule_title}\n'
        message += f'Actor: {actor}\n'
        message += f'Event Count: {event_count}\n'
        message += f'Threshold: {threshold_count}\n'
        message += f'Time Window: {window_minutes} minutes\n'
        message += '-' * 40 + '\n'

    subject = f"[AWS CloudTrail Alert][{severity}] {records.get('eventName', 'N/A')}"
    if correlated_events:
        subject = f"[CORRELATED] {subject}"
    if threshold_info:
        subject = f"[THRESHOLD EXCEEDED] {subject}"

    try:
        response = sns_client.publish(
            TopicArn=sns_topic,
            Message=message,
            Subject=subject[:100]
        )
        logging.info(f"SNS notification sent to {sns_topic}")
    except ClientError as e:
        logging.error(f"Failed to send SNS notification: {str(e)}")
