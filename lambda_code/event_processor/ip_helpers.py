from utils import get_nested_value
import logging
import requests
from typing import Dict, Any, Optional, Tuple

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
                <div>IP Address: <span class="value">{ip}</span></div>
                <div>Private IP address</div>
            </div>
            """
    else:
        # Safely access security indicators
        security = data.get("security", {})
        if not security or not isinstance(security, dict):
            security = {}
            
        security_indicators = ", ".join(
            [key.upper() for key, value in security.items() if value]
        )
        
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
            
        maps_url = f"https://www.google.com/maps/search/{location.get('latitude', 'unknown')},{location.get('longitude', 'unknown')}"
        virustotal_url = f"https://www.virustotal.com/gui/ip-address/{ip}"
        greynoise_url = f"https://viz.greynoise.io/ip/{ip}"
        
        sections_html = f"""
        <div class="section">
                <div class="section-title">IP Information</div>
                <div class="ip-links">
                    <a href="{virustotal_url}" target="_blank">VirusTotal</a>
                    <a href="{greynoise_url}" target="_blank">GreyNoise</a>
                </div>
                <div>IP Address: <span class="value">{data.get('ip', ip)}</span></div>
                <div>Country: <span class="value">{location.get('country', 'unknown')}</span></div>
                <div>City/Region: <span class="value">{location.get('city', 'unknown')}/{location.get('region', 'unknown')}</span></div>
                <div>Continent: <span class="value">{location.get('continent', 'unknown')}</span></div>
                <div>Geolocation: <a href="{maps_url}" target="_blank"><span class="value">{location.get('latitude', 'unknown')}, {location.get('longitude', 'unknown')}</span></a></div>
                <div>Time Zone: <span class="value">{location.get('time_zone', 'unknown')}</span></div>
                <div>Is in European Union: <span class="value">{'Yes' if location.get('is_in_european_union', False) else 'No'}</span></div>
                <div>Security Indicators: <span class="value">{security_indicators}</span></div>
                <div>Network Range: <span class="value">{network.get('network', 'unknown')}</span></div>
                <div>Autonomous System: <span class="value">{network.get('autonomous_system_organization', 'unknown')} ({network.get('autonomous_system_number', 'unknown')})</span></div>
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