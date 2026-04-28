# styles.py
# This module contains functions related to styles generation


def generate_style() -> str:
    """
    Generates CSS styles for the HTML email.
    
    Returns:
        str: CSS styles
    """
    style = """<style>
        @import url('https://fonts.googleapis.com/css2?family=Inter+Tight:wght@600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', 'Roboto', Arial, sans-serif;
            background-color: #E2F1F8;
            color: #1D2832;
            line-height: 1.6;
        }

        .email-shell {
            width: 100%;
            padding: 24px 12px 28px;
            box-sizing: border-box;
            background-color: #E2F1F8;
        }

        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #FFFFFF;
            border: 1px solid #C6E3EF;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 8px 24px rgba(2, 48, 71, 0.12);
        }

        .header {
            background-color: #023047;
            padding: 24px 28px 22px;
            color: #FFFFFF;
        }

        .header-kicker {
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.14em;
            color: #8ECAE6;
            margin-bottom: 8px;
        }

        .header-title {
            font-family: 'Inter Tight', 'Inter', Arial, sans-serif;
            font-size: 26px;
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
            padding: 18px 28px 8px;
            background-color: #FAFBFC;
            border-bottom: 1px solid #E8ECEF;
        }

        .intro-title {
            font-size: 15px;
            font-weight: 600;
            color: #023047;
            margin-bottom: 4px;
        }

        .intro-text {
            font-size: 14px;
            color: #44515B;
        }

        .section {
            margin: 16px 20px;
            border: 1px solid #D3DADE;
            border-radius: 8px;
            overflow: hidden;
            background-color: #FFFFFF;
            box-shadow: 0 1px 3px rgba(2, 48, 71, 0.06);
        }

        .section-title {
            background-color: #023047;
            color: #FFFFFF;
            padding: 12px 16px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .section-body {
            padding: 0;
        }

        .detail-row {
            padding: 10px 16px;
            border-top: 1px solid #E8ECEF;
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
            color: #5E6B75;
        }

        .value {
            color: #1D2832;
            font-weight: 500;
            word-break: break-word;
        }

        .value-strong {
            color: #023047;
            font-weight: 600;
        }

        .value-mono,
        .mono {
            font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
            font-size: 12px;
            color: #0F1820;
            word-break: break-all;
        }

        .severity-pill {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            border: 1px solid transparent;
        }

        .severity-critical {
            background-color: #5b0a18;
            color: #ffe1e6;
            border-color: #7a1224;
        }

        .severity-high {
            background-color: #fde2d4;
            color: #8a2a05;
            border-color: #f3b58e;
        }

        .severity-medium {
            background-color: #fff1cf;
            color: #7a4d00;
            border-color: #f1cf7a;
        }

        .severity-low {
            background-color: #d9eef7;
            color: #145e72;
            border-color: #9bd1e3;
        }

        .severity-info,
        .severity-unknown {
            background-color: #e8ecef;
            color: #2f3a44;
            border-color: #c0cad1;
        }

        .notice {
            margin: 12px 16px 0;
            padding: 10px 12px;
            border-radius: 8px;
            background-color: #EFF6FF;
            border: 1px solid #C6E3EF;
            color: #145E72;
            font-size: 13px;
            font-weight: 500;
        }

        .correlation-warning,
        .threshold-warning {
            margin: 12px 16px 0;
            padding: 10px 12px;
            border-radius: 8px;
            background-color: #FFF1CF;
            border: 1px solid #F1CF7A;
            color: #7A4D00;
            font-size: 13px;
            font-weight: 500;
        }

        .correlated-event,
        .threshold-details {
            margin: 12px 16px 16px;
            border: 1px solid #E8ECEF;
            border-radius: 8px;
            background-color: #F4F6F8;
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
            color: #1D2832;
        }

        .section a {
            color: #1A7F99;
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
            background-color: #023047;
            color: #FFFFFF !important;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            font-size: 13px;
        }

        .console-button:hover {
            background-color: #145E72;
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
            border-top: 1px solid #E8ECEF;
        }

        .resources-list li:first-child {
            border-top: none;
        }

        .resource-item {
            padding: 10px 12px;
            background-color: #F4F6F8;
            border-radius: 8px;
            border: 1px solid #E8ECEF;
        }

        .resource-type {
            margin-bottom: 6px;
            color: #023047;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .resource-arn,
        .resource-name,
        .resource-detail {
            margin-top: 4px;
            color: #1D2832;
            word-break: break-word;
        }

        .resource-arn {
            font-family: 'JetBrains Mono', 'SFMono-Regular', Consolas, monospace;
            font-size: 12px;
            word-break: break-all;
        }

        .highlight {
            background-color: #FFF1CF;
            padding: 2px 4px;
            border-radius: 4px;
        }

        .emphasis {
            font-weight: 600;
            color: #023047;
        }

        .inferred-resource {
            margin-top: 8px;
            padding: 10px 12px;
            background-color: #F4F6F8;
            border-left: 4px solid #219EBC;
            border-radius: 0 8px 8px 0;
        }

        .footer {
            padding: 8px 28px 24px;
            text-align: center;
            font-size: 12px;
            color: #5E6B75;
            border-top: 1px solid #E8ECEF;
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
                font-size: 23px;
            }
        }
    </style>"""
    return style