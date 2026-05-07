import os
import sys
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ip_helpers import get_ip_information  # noqa: E402


def test_get_ip_information_skips_non_ip_values():
    with patch("ip_helpers.requests.get") as mock_get:
        assert get_ip_information("cloudtrail.amazonaws.com", "api-key") is None
        mock_get.assert_not_called()


def test_get_ip_information_skips_non_public_ip_values():
    with patch("ip_helpers.requests.get") as mock_get:
        result = get_ip_information("10.0.0.5", "api-key")

        assert result == {"message": "10.0.0.5 is a private IP address"}
        mock_get.assert_not_called()


def test_get_ip_information_uses_canonical_ip_and_timeout():
    response = Mock()
    response.json.return_value = {"ip": "8.8.8.8"}

    with patch("ip_helpers.requests.get", return_value=response) as mock_get:
        assert get_ip_information("8.8.8.8", "api-key") == {"ip": "8.8.8.8"}

        mock_get.assert_called_once_with("https://vpnapi.io/api/8.8.8.8?key=api-key", timeout=5)
        response.raise_for_status.assert_called_once()