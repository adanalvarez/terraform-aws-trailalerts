import boto3
from botocore.exceptions import ClientError
import html
import logging
import os
from typing import List, Dict, Any, Optional


KNOWN_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _escape_text(value: Any) -> str:
    """Safely escape values rendered into the HTML email."""
    return html.escape(str(value if value is not None else "N/A"))


def _render_detail_row(label: str, value: Any, value_class: str = "value") -> str:
    """Render a dashboard-style key/value row for the email template."""
    return f"""
        <div class="detail-row">
            <div class="detail-label">{html.escape(label)}</div>
            <div class="{value_class}">{_escape_text(value)}</div>
        </div>
    """


def _render_detail_row_html(label: str, value_html: str, value_class: str = "value") -> str:
    """Render a key/value row whose value is already safe HTML."""
    return f"""
        <div class="detail-row">
            <div class="detail-label">{html.escape(label)}</div>
            <div class="{value_class}">{value_html}</div>
        </div>
    """


def _normalize_severity(value: Any) -> str:
    severity = str(value or "unknown").strip().lower()
    return severity if severity in KNOWN_SEVERITIES else "unknown"


def _display_severity(value: Any) -> str:
    return _normalize_severity(value).title()


def _build_alert_subject(rule: Dict[str, Any],
                         correlated_events: Optional[List[Dict[str, Any]]] = None,
                         threshold_info: Optional[Dict[str, Any]] = None) -> str:
    rule_title = str(rule.get("title", "Unknown Rule"))
    severity = _display_severity(rule.get("level", "unknown"))
    subject_parts = ["TrailAlerts", severity, rule_title]
    if correlated_events:
        subject_parts.append("correlated activity")
    if threshold_info:
        subject_parts.append("threshold activity")
    return " - ".join(subject_parts)


def _generate_plain_text_alert(event: Dict[str, Any],
                               rule: Dict[str, Any],
                               correlated_events: Optional[List[Dict[str, Any]]] = None,
                               threshold_info: Optional[Dict[str, Any]] = None) -> str:
    lines = [
        "TrailAlerts alert",
        f"Rule: {rule.get('title', 'Unknown Rule')}",
        f"Severity: {_display_severity(rule.get('level', 'unknown'))}",
        f"Event: {event.get('eventName', 'N/A')}",
        f"Event Source: {event.get('eventSource', 'N/A')}",
        f"Time: {event.get('eventTime', 'N/A')}",
        f"Actor: {event.get('actor') or event.get('userIdentity', {}).get('arn', 'N/A')}",
        f"Source IP: {event.get('sourceIPAddress', 'N/A')}",
        f"Region: {event.get('awsRegion', 'N/A')}",
        f"Account ID: {event.get('recipientAccountId', event.get('userIdentity', {}).get('accountId', 'N/A'))}",
    ]

    if correlated_events:
        lines.append("")
        lines.append("Correlated activity was identified in the same investigation window.")
        for correlated_event in correlated_events:
            lines.extend([
                f"Related Rule: {correlated_event.get('sigmaRuleTitle', 'N/A')}",
                f"Time: {correlated_event.get('timestamp', 'N/A')}",
                f"Actor: {correlated_event.get('actor', 'N/A')}",
                f"Target: {correlated_event.get('target', 'N/A')}",
            ])

    if threshold_info:
        event_count = threshold_info.get('eventCount', threshold_info.get('event_count', 0))
        threshold_count = threshold_info.get('thresholdCount', threshold_info.get('threshold_count', 0))
        window_minutes = threshold_info.get('windowMinutes', threshold_info.get('window_minutes', 0))
        lines.extend([
            "",
            "Activity met the configured alert threshold.",
            f"Event Count: {event_count}",
            f"Threshold: {threshold_count}",
            f"Time Window: {window_minutes} minutes",
        ])

    return "\n".join(str(line) for line in lines)


def generate_email_html(style: str, sections: List[str], alert_title: str = "Security event summary") -> str:
    """
    Generates an HTML email template with CloudTrail information, IP information, and CloudTrail information.
    
    Args:
        style: CSS styles as string
        sections: List of HTML sections to include
        
    Returns:
        str: Complete HTML email template
    """
    try:
        valid_sections = [section for section in sections if section and section.strip()]
        combined_sections = "".join(valid_sections)
        safe_alert_title = _escape_text(alert_title or "Security event summary")

        html_template = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{safe_alert_title} - TrailAlerts Alert</title>
                {style}
            </head>
            <body>
                <div class="email-shell">
                    <div class="container">
                        <div class="header">
                            <div class="header-kicker">trailalerts &middot; alert</div>
                            <div class="header-title">{safe_alert_title}</div>
                        </div>
                        <div class="intro">
                            <div class="intro-title">Security event summary</div>
                            <div class="intro-text">
                                A detection in your AWS environment matched one of your monitoring rules. Review the summary, evidence, and CloudTrail context below.
                            </div>
                        </div>
                        {combined_sections}
                        <div class="footer">
                            TrailAlerts notification. Review the dashboard for full event history, filtering, and investigation context.
                        </div>
                    </div>
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
                <h1>{_escape_text(alert_title or 'TrailAlerts Alert')}</h1>
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
                {_render_detail_row("Rule", event.get("sigmaRuleTitle", "N/A"))}
                {_render_detail_row("Time", event.get("timestamp", "N/A"), "value value-mono")}
                {_render_detail_row("Actor", event.get("actor", "N/A"), "value value-mono")}
                {_render_detail_row("Target", event.get("target", "N/A"), "value value-mono")}
            </div>
        """
        events_html.append(event_html)

    return f"""
        <div class="section">
            <div class="section-title">Correlated Activity</div>
            <div class="correlation-warning">Related activity was identified in the same investigation window.</div>
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
            <div class="section-title">Threshold Activity</div>
            <div class="threshold-warning">Activity met the configured alert threshold.</div>
            <div class="threshold-details">
                {_render_detail_row("Rule", rule_title)}
                {_render_detail_row("Actor", actor, "value value-mono")}
                {_render_detail_row("Event Count", event_count, "value value-strong")}
                {_render_detail_row("Threshold", threshold_count, "value value-strong")}
                {_render_detail_row("Time Window", f"{window_minutes} minutes")}
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
    if not rule:
        return ""

    sections = []

    if rule.get("title"):
        sections.append(_render_detail_row("Rule", rule["title"], "value value-strong"))
    if rule.get("level"):
        severity_level = _normalize_severity(rule.get("level"))
        severity_badge = (
            f"<span class='severity-pill severity-{severity_level}'>"
            f"{_escape_text(_display_severity(rule.get('level')))}</span>"
        )
        sections.append(_render_detail_row_html("Severity", severity_badge))
    if rule.get("id"):
        sections.append(_render_detail_row("Rule ID", rule["id"], "value value-mono"))
    if rule.get("description"):
        sections.append(_render_detail_row("Description", rule["description"]))
    if rule.get("author"):
        sections.append(_render_detail_row("Author", rule["author"]))
    if rule.get("references"):
        refs = []
        for reference in rule["references"]:
            escaped_ref = _escape_text(reference)
            safe_href = html.escape(str(reference), quote=True)
            refs.append(
                f"<li><a href='{safe_href}' target='_blank' rel='noopener noreferrer'>{escaped_ref}</a></li>"
            )
        sections.append(
            f"""
            <div class="detail-row">
                <div class="detail-label">References</div>
                <ul>{''.join(refs)}</ul>
            </div>
            """
        )

    return f"""
        <div class="section">
            <div class="section-title">Alert Summary</div>
            <div class="section-body">
                {"".join(sections)}
            </div>
        </div>
    """


def ses_send_email(html_content: str, event: Dict[str, Any], source_email: str, 
                  destination_email: str, rule: Dict[str, Any],
                  correlated_events: List[Dict[str, Any]] = None,
                  threshold_info: Dict[str, Any] = None) -> bool:
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

    Returns:
        bool: True when SES accepted the email request, False otherwise
    """
    ses_client = boto3.client("ses")
    subject = _build_alert_subject(rule, correlated_events, threshold_info)
    text_content = _generate_plain_text_alert(event, rule, correlated_events, threshold_info)

    try:
        response = ses_client.send_email(
            Source=source_email,
            Destination={"ToAddresses": [destination_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {
                    "Html": {"Data": html_content},
                    "Text": {"Data": text_content},
                },
            },
        )
        logging.info(f"Email sent: {response['MessageId']}")
        return True
    except ClientError as e:
        logging.error(f"Failed to send email: {str(e)}")
        return False

def sns_send_email(sns_topic: str, records: Dict[str, Any], 
                  correlated_events: List[Dict[str, Any]] = None,
                  threshold_info: Dict[str, Any] = None,
                  rule_metadata: Dict[str, Any] = None) -> bool:
    """
    Sends a message to an SNS topic.
    
    Args:
        sns_topic: The SNS topic ARN
        records: The CloudTrail event records
        correlated_events: Optional list of correlated events
        threshold_info: Optional dictionary containing threshold information
        rule_metadata: Optional rule metadata containing severity information

    Returns:
        bool: True when SNS accepted the publish request, False otherwise
    """
    sns_client = boto3.client("sns")
    
    # Get severity from rule metadata
    severity = "Unknown"
    if rule_metadata and "level" in rule_metadata:
        severity = _display_severity(rule_metadata["level"])
    
    message = f'TrailAlerts alert\n'
    message += f'Severity: {severity}\n'
    message += f'Event: {records.get("eventName", "N/A")}\n'
    message += f'Event Source: {records.get("eventSource", "N/A")}\n'
    message += f'Principal ID: {records.get("userIdentity", {}).get("principalId", "N/A")}\n'
    message += f'Account ID: {records.get("userIdentity", {}).get("accountId", "N/A")}\n'
    message += f'AWS Region: {records.get("awsRegion", "N/A")}\n'
    message += f'Source IP Address: {records.get("sourceIPAddress", "N/A")}\n'
    message += f'Request Parameters: {records.get("requestParameters", "N/A")}\n'

    # Add correlation information if available
    if correlated_events:
        message += "\nCorrelated activity:\n"
        message += "Related activity was identified in the same investigation window.\n\n"
        for event in correlated_events:
            message += f'Related Rule: {event.get("sigmaRuleTitle", "N/A")}\n'
            message += f'Time: {event.get("timestamp", "N/A")}\n'
            message += f'Actor: {event.get("actor", "N/A")}\n'
            message += f'Target: {event.get("target", "N/A")}\n'
            message += '-' * 40 + '\n'
    
    # Add threshold information if available
    if threshold_info:
        message += "\nThreshold activity:\n"
        message += "Activity met the configured alert threshold.\n\n"
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

    subject_rule = rule_metadata or {"title": records.get('eventName', 'N/A'), "level": severity}
    subject = _build_alert_subject(subject_rule, correlated_events, threshold_info)

    try:
        response = sns_client.publish(
            TopicArn=sns_topic,
            Message=message,
            Subject=subject[:100]
        )
        logging.info(f"SNS notification sent to {sns_topic}")
        return True
    except ClientError as e:
        logging.error(f"Failed to send SNS notification: {str(e)}")
        return False
