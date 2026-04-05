"""Tests for webhook_helpers module."""
import json
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError

from webhook_helpers import webhook_send


class TestWebhookSend(unittest.TestCase):
    """Tests for the webhook_send function."""

    def setUp(self):
        self.url = "https://hooks.example.com/alert"
        self.headers = {"Authorization": "Bearer tok123"}
        self.event = {
            "eventName": "DeleteBucket",
            "eventSource": "s3.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "requestParameters": {"bucketName": "my-bucket"},
            "eventTime": "2025-01-01T00:00:00Z",
        }
        self.rule = {
            "title": "S3 Bucket Deleted",
            "id": "abc-123",
            "level": "high",
            "description": "Someone deleted a bucket",
            "author": "SecurityTeam",
            "references": ["https://example.com"],
        }

    @patch("webhook_helpers.urlopen")
    def test_successful_post(self, mock_urlopen):
        """200-level response returns True."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = webhook_send(self.url, self.headers, self.event, self.rule)

        self.assertTrue(result)
        # Verify the request was made
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        self.assertEqual(req.full_url, self.url)
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.get_header("Content-type"), "application/json")
        self.assertEqual(req.get_header("Authorization"), "Bearer tok123")

    @patch("webhook_helpers.urlopen")
    def test_payload_structure(self, mock_urlopen):
        """Verify JSON payload contains expected keys."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        webhook_send(self.url, self.headers, self.event, self.rule)

        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))

        self.assertEqual(payload["source"], "TrailAlerts")
        self.assertIn("timestamp", payload)
        self.assertEqual(payload["rule"]["title"], "S3 Bucket Deleted")
        self.assertEqual(payload["rule"]["level"], "high")
        self.assertEqual(payload["event"]["eventName"], "DeleteBucket")
        self.assertEqual(payload["event"]["awsRegion"], "us-east-1")
        self.assertEqual(payload["event"]["userIdentity"]["userName"], "alice")
        self.assertNotIn("correlatedEvents", payload)
        self.assertNotIn("thresholdInfo", payload)

    @patch("webhook_helpers.urlopen")
    def test_payload_with_correlated_events(self, mock_urlopen):
        """Correlated events are included in the payload."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        correlated = [
            {"sigmaRuleTitle": "Login Anomaly", "timestamp": "2025-01-01T00:00:00Z",
             "actor": "alice", "target": "console"},
        ]
        webhook_send(self.url, self.headers, self.event, self.rule,
                     correlated_events=correlated)

        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))

        self.assertEqual(len(payload["correlatedEvents"]), 1)
        self.assertEqual(payload["correlatedEvents"][0]["ruleTitle"], "Login Anomaly")

    @patch("webhook_helpers.urlopen")
    def test_payload_with_threshold_info(self, mock_urlopen):
        """Threshold info is included in the payload."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        threshold = {
            "eventCount": 10, "thresholdCount": 5,
            "windowMinutes": 15, "actor": "alice",
            "ruleTitle": "Brute Force",
        }
        webhook_send(self.url, self.headers, self.event, self.rule,
                     threshold_info=threshold)

        req = mock_urlopen.call_args[0][0]
        payload = json.loads(req.data.decode("utf-8"))

        self.assertEqual(payload["thresholdInfo"]["eventCount"], 10)
        self.assertEqual(payload["thresholdInfo"]["thresholdCount"], 5)

    @patch("webhook_helpers.urlopen")
    def test_http_error_returns_false(self, mock_urlopen):
        """HTTPError is caught and returns False."""
        mock_urlopen.side_effect = HTTPError(
            self.url, 403, "Forbidden", {}, None
        )
        result = webhook_send(self.url, self.headers, self.event, self.rule)
        self.assertFalse(result)

    @patch("webhook_helpers.urlopen")
    def test_url_error_returns_false(self, mock_urlopen):
        """URLError (network issue) is caught and returns False."""
        mock_urlopen.side_effect = URLError("Connection refused")
        result = webhook_send(self.url, self.headers, self.event, self.rule)
        self.assertFalse(result)

    @patch("webhook_helpers.urlopen")
    def test_empty_headers(self, mock_urlopen):
        """Empty headers dict still sets Content-Type."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        webhook_send(self.url, {}, self.event, self.rule)

        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("Content-type"), "application/json")
        # No Authorization header when empty
        self.assertIsNone(req.get_header("Authorization"))

    @patch("webhook_helpers.urlopen")
    def test_none_headers(self, mock_urlopen):
        """None headers are handled gracefully."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        webhook_send(self.url, None, self.event, self.rule)

        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_header("Content-type"), "application/json")


if __name__ == "__main__":
    unittest.main()
