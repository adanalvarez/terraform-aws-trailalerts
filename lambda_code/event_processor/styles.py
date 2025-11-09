# styles.py
# This module contains functions related to styles generation


def generate_style() -> str:
    """
    Generates CSS styles for the HTML email.
    
    Returns:
        str: CSS styles
    """
    style = """<style>
        @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');

        body {
            font-family: 'Roboto', sans-serif;
            background-color: #f7f8fc;
            line-height: 1.6;
        }
        .container {
            border: 1px solid #e3e7ed;
            padding: 20px;
            max-width: 600px;
            margin: 40px auto;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .header {
            text-align: center;
            font-weight: bold;
            font-size: 24px;
            margin-bottom: 30px;
            color: #161A30;
        }
        .section {
            border: 1px solid #e3e7ed;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .section-title {
            background-color: #161A30;
            color: white;
            padding: 10px;
            border-radius: 3px;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .value {
            color: #161A30;
            font-weight: bold;
        }
        .ip-links {
            text-align: right;
            margin-top: -10px;
        }
        .ip-links a {
            display: inline-block;
            margin-left: 10px;
            color: #fff;
            background-color: #5cb85c;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            text-decoration: none;
        }
        .ip-links a:hover {
            background-color: #4cae4c;
        }
        .correlation-warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ffeeba;
            border-radius: 4px;
            font-weight: bold;
        }
        .correlated-event {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .correlated-event:hover {
            background-color: #e9ecef;
        }
        @media (max-width: 600px) {
            .container {
                padding: 10px;
                margin: 10px;
            }
            .header {
                font-size: 20px;
            }
        }
        
        /* Severity indicators */
        .severity-critical {
            color: #ffffff;
            background-color: #cc0000;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
        }
        .severity-high {
            color: #ffffff;
            background-color: #ff4444;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
        }
        .severity-medium {
            color: #000000;
            background-color: #ffcc00;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
        }
        .severity-low {
            color: #000000;
            background-color: #00cc00;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
        }
        .severity-info {
            color: #ffffff;
            background-color: #0066cc;
            padding: 2px 6px;
            border-radius: 3px;
            font-weight: bold;
        }
        
        /* Rule information styling */
        .section ul {
            margin: 5px 0;
            padding-left: 20px;
        }
        .section li {
            margin: 3px 0;
        }
        
        .cloudtrail-link {
            margin: 15px 0;
            text-align: right;
        }
        
        .console-button {
            display: inline-block;
            padding: 8px 16px;
            background-color: #232f3e;  /* AWS Console dark blue */
            color: #ffffff !important;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            transition: background-color 0.2s;
        }
        
        .console-button:hover {
            background-color: #1a242f;
            text-decoration: none;
        }
        
        /* Resources list styling */
        .resources-list {
            margin: 10px 0;
            padding-left: 20px;
            list-style-type: disc;
        }
        
        .resources-list li {
            margin-bottom: 5px;
            padding: 5px;
            background-color: #f8f9fa;
            border-radius: 3px;
            border: 1px solid #eaecef;
        }
        
        /* Make sure the button is visible on dark mode email clients */
        @media (prefers-color-scheme: dark) {
            .console-button {
                background-color: #0073bb;
            }
            .console-button:hover {
                background-color: #005d99;
            }
        }
        
        /* Enhanced Resource Section Styling */
        .section-resources {
            margin: 15px 0;
        }
        
        .section-subtitle {
            font-weight: bold;
            margin-bottom: 10px;
            color: #161A30;
            border-bottom: 1px solid #e3e7ed;
            padding-bottom: 5px;
        }
        
        .resources-list {
            margin: 10px 0;
            padding-left: 20px;
            list-style-type: none;
        }
        
        .resources-list li {
            margin-bottom: 10px;
            padding: 0;
            background-color: transparent;
            border: none;
        }
        
        .resource-item {
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
            border: 1px solid #dee2e6;
        }
        
        .resource-type {
            margin-bottom: 5px;
            color: #161A30;
        }
        
        .resource-arn {
            margin-bottom: 5px;
            word-break: break-all;
        }
        
        .resource-name {
            margin-bottom: 5px;
        }
        
        .resource-detail {
            color: #555;
            margin-top: 2px;
            font-size: 0.95em;
        }
        
        .highlight {
            background-color: #ffffd6;
            padding: 2px 4px;
            border-radius: 3px;
        }
        
        .emphasis {
            font-weight: bold;
            color: #161A30;
        }
        
        .inferred-resource {
            padding: 10px;
            background-color: #f8f9fa;
            border-left: 3px solid #161A30;
            margin: 5px 0;
            border-radius: 0 4px 4px 0;
        }
    </style>"""
    return style