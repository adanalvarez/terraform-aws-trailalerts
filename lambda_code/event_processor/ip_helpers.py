from utils import get_nested_value
import html
import logging
import requests
from typing import Dict, Any, Optional, Tuple
from urllib.parse import quote


def _escape_text(value: Any) -> str:
    return html.escape(str(value if value is not None else "unknown"))


def _detail_row(label: str, value: Any, value_class: str = "value") -> str:
    return f"""
        <div class="detail-row">
            <div class="detail-label">{_escape_text(label)}</div>
            <div class="{value_class}">{_escape_text(value)}</div>
        </div>
    """


def _detail_row_html(label: str, value_html: str, value_class: str = "value") -> str:
    return f"""
        <div class="detail-row">
            <div class="detail-label">{_escape_text(label)}</div>
            <div class="{value_class}">{value_html}</div>
        </div>
    """

def get_ip_information_section(event: Dict[str, Any], api_key: Optional[str]) -> Tuple[str, Optional[str]]:
    """
    Retrieves IP information based on various paths from the event and formats it.
    
    Args:
        event: The CloudTrail event
        api_key: The VPN API key
        
    Returns:
        Tuple[str, Optional[str]]: Tuple containing formatted HTML and IP address
    """
    # Safety check for event and sourceIPAddress
    if not event or not isinstance(event, dict):
        logging.warning("Invalid event provided to get_ip_information_section")
        return "", None
        
    ip_address_v4 = event.get("sourceIPAddress")
    
    logging.debug(f"Processing IP: {ip_address_v4}")
    if api_key and ip_address_v4:
        ip_info = get_ip_information(ip_address_v4, api_key)
        return (
            (format_ip_information(ip_address_v4, ip_info), ip_address_v4)
            if ip_info
            else ("", None)
        )
    return "", None


def format_ip_information(ip: str, data: Dict[str, Any]) -> str:
    """
    Formats IP information into HTML.
    
    Args:
        ip: The IP address
        data: The IP information data
        
    Returns:
        str: HTML formatted IP information
    """
    if not data:
        return ""
        
    if "is a private IP address" in str(data):
        logging.info(f"Found private IP address: {ip}")
        sections_html = f"""
           <div class="section">
                <div class="section-title">IP Information</div>
                <div class="section-body">
                    {_detail_row("IP Address", ip, "value value-mono")}
                    <div class="notice">Private IP address</div>
                </div>
            </div>
            """
    else:
        # Safely access security indicators
        security = data.get("security", {})
        if not security or not isinstance(security, dict):
            security = {}
            
        security_indicators = ", ".join(
            [key.replace("_", " ").title() for key, value in security.items() if value]
        ) or "None reported"
        
        # Safely access location data
        location = data.get("location", {})
        if not location or not isinstance(location, dict):
            location = {
                "latitude": "unknown", 
                "longitude": "unknown",
                "country": "unknown",
                "city": "unknown",
                "region": "unknown",
                "continent": "unknown",
                "time_zone": "unknown",
                "is_in_european_union": False
            }
            
        # Safely access network data
        network = data.get("network", {})
        if not network or not isinstance(network, dict):
            network = {
                "network": "unknown",
                "autonomous_system_organization": "unknown",
                "autonomous_system_number": "unknown"
            }
            
        latitude = str(location.get('latitude', 'unknown'))
        longitude = str(location.get('longitude', 'unknown'))
        encoded_ip = quote(str(ip), safe=".:")
        encoded_coordinates = quote(f"{latitude},{longitude}", safe=",.-")

        maps_url = f"https://www.google.com/maps/search/{encoded_coordinates}"
        virustotal_url = f"https://www.virustotal.com/gui/ip-address/{encoded_ip}"
        greynoise_url = f"https://viz.greynoise.io/ip/{encoded_ip}"
        links_html = (
            f"<a href='{html.escape(virustotal_url, quote=True)}' target='_blank' rel='noopener noreferrer'>VirusTotal</a> "
            f"<a href='{html.escape(greynoise_url, quote=True)}' target='_blank' rel='noopener noreferrer'>GreyNoise</a>"
        )
        geolocation_html = (
            f"<a href='{html.escape(maps_url, quote=True)}' target='_blank' rel='noopener noreferrer'>"
            f"<span class='value value-mono'>{_escape_text(latitude)}, {_escape_text(longitude)}</span></a>"
        )
        
        sections_html = f"""
        <div class="section">
                <div class="section-title">IP Information</div>
                <div class="section-body">
                    {_detail_row_html("Investigation Links", links_html)}
                    {_detail_row("IP Address", data.get('ip', ip), "value value-mono")}
                    {_detail_row("Country", location.get('country', 'unknown'))}
                    {_detail_row("City/Region", f"{location.get('city', 'unknown')}/{location.get('region', 'unknown')}")}
                    {_detail_row("Continent", location.get('continent', 'unknown'))}
                    {_detail_row_html("Geolocation", geolocation_html)}
                    {_detail_row("Time Zone", location.get('time_zone', 'unknown'), "value value-mono")}
                    {_detail_row("European Union", 'Yes' if location.get('is_in_european_union', False) else 'No')}
                    {_detail_row("Security Indicators", security_indicators)}
                    {_detail_row("Network Range", network.get('network', 'unknown'), "value value-mono")}
                    {_detail_row("Autonomous System", f"{network.get('autonomous_system_organization', 'unknown')} ({network.get('autonomous_system_number', 'unknown')})")}
                </div>
        </div>
        """
    return sections_html


def get_ip_information(ip: str, api_key: str) -> Optional[Dict[str, Any]]:
    """
    Fetches IP information from vpnapi.io API.
    
    Args:
        ip: The IP address to lookup
        api_key: The VPN API key
        
    Returns:
        Optional[Dict[str, Any]]: IP information data or None if request fails
    """
    if not ip or not api_key:
        return None
        
    url = f"https://vpnapi.io/api/{ip}?key={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        logging.info(f"Retrieved IP information for {ip}")
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Failed to retrieve IP information: {str(e)}")
        return None
    except ValueError as e:
        logging.error(f"Failed to parse IP information response: {str(e)}")
        return None