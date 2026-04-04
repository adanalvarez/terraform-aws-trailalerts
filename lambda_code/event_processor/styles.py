# styles.py
# This module contains functions related to styles generation


def generate_style() -> str:
    """
    Generates CSS styles for the HTML email.
    
    Returns:
        str: CSS styles
    """
    style = """<style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', 'Roboto', Arial, sans-serif;
            background-color: #8ECAE6;
            color: #2B2D31;
            line-height: 1.6;
        }

        .email-shell {
            width: 100%;
            padding: 24px 12px 28px;
            box-sizing: border-box;
            background-color: #8ECAE6;
        }

        .container {
            max-width: 760px;
            margin: 0 auto;
            background-color: #FFFFFF;
            border: 1px solid #D1D5DB;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(1, 37, 61, 0.12);
        }

        .header {
            background-color: #01253D;
            padding: 28px 32px 24px;
            color: #FFFFFF;
        }

        .header-kicker {
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            color: rgba(255, 255, 255, 0.72);
            margin-bottom: 8px;
        }

        .header-title {
            font-size: 28px;
            line-height: 1.2;
            font-weight: 700;
            margin: 0 0 6px;
            color: #FFFFFF;
        }

        .header-subtitle {
            font-size: 14px;
            color: rgba(255, 255, 255, 0.84);
            max-width: 620px;
        }

        .intro {
            padding: 20px 32px 8px;
            background-color: #F8FBFD;
            border-bottom: 1px solid #E8EAED;
        }

        .intro-title {
            font-size: 15px;
            font-weight: 600;
            color: #01253D;
            margin-bottom: 4px;
        }

        .intro-text {
            font-size: 14px;
            color: #4B5563;
        }

        .section {
            margin: 16px 24px;
            border: 1px solid #D1D5DB;
            border-radius: 12px;
            overflow: hidden;
            background-color: #FFFFFF;
            box-shadow: 0 1px 3px rgba(1, 37, 61, 0.06);
        }

        .section-title {
            background-color: #01253D;
            color: #FFFFFF;
            padding: 12px 16px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .section-body {
            padding: 0;
        }

        .detail-row {
            padding: 10px 16px;
            border-top: 1px solid #E8EAED;
        }

        .detail-row:first-child {
            border-top: none;
        }

        .detail-label {
            display: block;
            margin-bottom: 2px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #6B7280;
        }

        .value {
            color: #01253D;
            font-weight: 600;
            word-break: break-word;
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .severity-critical {
            background-color: #FEF2F2;
            color: #B91C1C;
        }

        .severity-high {
            background-color: #FFF7ED;
            color: #C2410C;
        }

        .severity-medium {
            background-color: #FFFBEB;
            color: #B45309;
        }

        .severity-low {
            background-color: #F0F9FF;
            color: #0369A1;
        }

        .severity-info {
            background-color: #EFF6FF;
            color: #1D4ED8;
        }

        .correlation-warning,
        .threshold-warning {
            margin: 12px 16px 0;
            padding: 12px 14px;
            border-radius: 10px;
            background-color: #FFF7ED;
            border: 1px solid #FCD34D;
            color: #9A3412;
            font-size: 13px;
            font-weight: 600;
        }

        .correlated-event,
        .threshold-details {
            margin: 12px 16px 16px;
            border: 1px solid #E8EAED;
            border-radius: 10px;
            background-color: #F5F6F8;
            overflow: hidden;
        }

        .correlated-event .detail-row,
        .threshold-details .detail-row {
            background-color: transparent;
        }

        .section ul {
            margin: 8px 0 0 18px;
            padding: 0;
        }

        .section li {
            margin: 4px 0;
            color: #2B2D31;
        }

        .section a {
            color: #17A2B8;
            text-decoration: none;
        }

        .section a:hover {
            text-decoration: underline;
        }

        .cloudtrail-link {
            padding: 12px 16px 16px;
            text-align: right;
        }

        .console-button {
            display: inline-block;
            padding: 10px 16px;
            background-color: #01253D;
            color: #FFFFFF !important;
            text-decoration: none;
            border-radius: 10px;
            font-weight: 600;
            font-size: 13px;
        }

        .console-button:hover {
            background-color: #17A2B8;
            text-decoration: none;
        }

        .resources-list {
            margin: 0;
            padding: 0;
            list-style: none;
        }

        .resources-list li {
            margin: 0;
            padding: 12px 16px;
            border-top: 1px solid #E8EAED;
        }

        .resources-list li:first-child {
            border-top: none;
        }

        .resource-item {
            padding: 10px 12px;
            background-color: #F5F6F8;
            border-radius: 10px;
            border: 1px solid #E8EAED;
        }

        .resource-type {
            margin-bottom: 6px;
            color: #01253D;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .resource-arn,
        .resource-name,
        .resource-detail {
            margin-top: 4px;
            color: #2B2D31;
            word-break: break-word;
        }

        .highlight {
            background-color: #FFFBEB;
            padding: 2px 4px;
            border-radius: 4px;
        }

        .emphasis {
            font-weight: 600;
            color: #01253D;
        }

        .inferred-resource {
            margin-top: 8px;
            padding: 10px 12px;
            background-color: #F5F6F8;
            border-left: 4px solid #17A2B8;
            border-radius: 0 8px 8px 0;
        }

        .footer {
            padding: 8px 32px 24px;
            text-align: center;
            font-size: 12px;
            color: #6B7280;
        }

        @media only screen and (max-width: 640px) {
            .email-shell {
                padding: 12px 6px 16px;
            }

            .header,
            .intro,
            .footer {
                padding-left: 18px;
                padding-right: 18px;
            }

            .section {
                margin: 12px;
            }

            .header-title {
                font-size: 24px;
            }
        }
    </style>"""
    return style