import os
import sys
import pytest
from unittest.mock import patch

# Ensure the parent package is importable without installing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from plugins.base import EventSourcePlugin
from plugins.registry import PluginRegistry
from plugins.config import PluginConfig
from plugins.cloudtrail import CloudTrailPlugin
from plugins.generic import GenericEventPlugin


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def registry():
    return PluginRegistry()


@pytest.fixture
def cloudtrail_plugin():
    return CloudTrailPlugin()


@pytest.fixture
def generic_plugin():
    return GenericEventPlugin()


@pytest.fixture
def full_registry(registry, cloudtrail_plugin, generic_plugin):
    """Registry with both plugins registered (cloudtrail first)."""
    registry.register_plugin(cloudtrail_plugin)
    registry.register_plugin(generic_plugin)
    return registry


# ---------------------------------------------------------------------------
# Helper: sample events
# ---------------------------------------------------------------------------
def _cloudtrail_event(**overrides):
    base = {
        "sigmaEventSource": "CloudTrail",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "eventType": "AwsConsoleSignIn",
        "sourceIPAddress": "203.0.113.1",
        "eventTime": "2025-01-15T10:30:00Z",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "test-user",
            "arn": "arn:aws:iam::123456789012:user/test-user",
            "principalId": "AIDACKCEVSQ6C2EXAMPLE",
            "accountId": "123456789012",
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        },
        "userAgent": "Mozilla/5.0",
        "requestParameters": {"roleName": "admin-role"},
        "responseElements": {"ConsoleLogin": "Success"},
        "errorCode": "",
        "errorMessage": "",
    }
    base.update(overrides)
    return base


def _generic_event(**overrides):
    base = {
        "eventType": "CustomEvent",
        "sourceIPAddress": "192.168.1.1",
        "eventTime": "2025-01-15T12:00:00Z",
        "awsRegion": "eu-west-1",
        "recipientAccountId": "987654321098",
        "userAgent": "custom-agent",
        "requestParameters": {},
        "responseElements": {},
        "errorCode": "",
        "errorMessage": "",
    }
    base.update(overrides)
    return base


# ===========================================================================
# PluginRegistry
# ===========================================================================
class TestPluginRegistration:
    def test_register_and_list(self, full_registry, cloudtrail_plugin, generic_plugin):
        assert len(full_registry.get_all_plugins()) == 2
        assert full_registry.get_plugin_by_name("cloudtrail") is cloudtrail_plugin
        assert full_registry.get_plugin_by_name("generic") is generic_plugin

    def test_get_plugin_by_name_missing(self, registry):
        assert registry.get_plugin_by_name("nonexistent") is None

    def test_empty_registry_returns_empty_list(self, registry):
        assert registry.get_all_plugins() == []

    def test_duplicate_registration_overwrites(self, registry, cloudtrail_plugin):
        registry.register_plugin(cloudtrail_plugin)
        new_plugin = CloudTrailPlugin()
        registry.register_plugin(new_plugin)
        assert registry.get_plugin_by_name("cloudtrail") is new_plugin
        assert len(registry.get_all_plugins()) == 1


class TestPluginRouting:
    def test_cloudtrail_event_routed_to_cloudtrail_plugin(self, full_registry, cloudtrail_plugin):
        plugin = full_registry.get_plugin_for_event(_cloudtrail_event())
        assert plugin is cloudtrail_plugin

    def test_generic_event_routed_to_generic_plugin(self, full_registry, generic_plugin):
        plugin = full_registry.get_plugin_for_event(_generic_event())
        assert plugin is generic_plugin

    def test_unknown_event_falls_back_to_generic(self, full_registry, generic_plugin):
        plugin = full_registry.get_plugin_for_event({"type": "UnknownType"})
        assert plugin is generic_plugin

    def test_empty_event_falls_back_to_generic(self, full_registry, generic_plugin):
        plugin = full_registry.get_plugin_for_event({})
        assert plugin is generic_plugin

    def test_no_plugins_returns_none(self, registry):
        assert registry.get_plugin_for_event({"any": "event"}) is None

    def test_only_cloudtrail_registered_returns_none_for_generic(self, registry, cloudtrail_plugin):
        registry.register_plugin(cloudtrail_plugin)
        assert registry.get_plugin_for_event(_generic_event()) is None


class TestPluginDiscovery:
    def test_discover_plugins_finds_concrete_classes(self):
        plugins = PluginRegistry.discover_plugins()
        names = {p.get_plugin_name() for p in plugins}
        assert "cloudtrail" in names
        assert "generic" in names

    def test_discovered_plugins_are_instances(self):
        plugins = PluginRegistry.discover_plugins()
        for p in plugins:
            assert isinstance(p, EventSourcePlugin)


# ===========================================================================
# CloudTrailPlugin — identity & metadata
# ===========================================================================
class TestCloudTrailPluginIdentity:
    def test_plugin_name(self, cloudtrail_plugin):
        assert cloudtrail_plugin.get_plugin_name() == "cloudtrail"

    def test_event_type(self, cloudtrail_plugin):
        assert cloudtrail_plugin.get_event_type() == "CloudTrail"

    def test_can_process_cloudtrail_event(self, cloudtrail_plugin):
        assert cloudtrail_plugin.can_process_event(_cloudtrail_event()) is True

    def test_cannot_process_generic_event(self, cloudtrail_plugin):
        assert cloudtrail_plugin.can_process_event(_generic_event()) is False

    def test_cannot_process_empty_event(self, cloudtrail_plugin):
        assert cloudtrail_plugin.can_process_event({}) is False


# ===========================================================================
# CloudTrailPlugin — extract_actor
# ===========================================================================
class TestCloudTrailExtractActor:
    def test_iam_user(self, cloudtrail_plugin):
        event = _cloudtrail_event()
        assert cloudtrail_plugin.extract_actor(event) == "test-user"

    def test_assumed_role(self, cloudtrail_plugin):
        event = _cloudtrail_event(userIdentity={
            "type": "AssumedRole",
            "arn": "arn:aws:iam::123456789012:role/test-role",
        })
        assert cloudtrail_plugin.extract_actor(event) == "arn:aws:iam::123456789012:role/test-role"

    def test_root_user(self, cloudtrail_plugin):
        event = _cloudtrail_event(userIdentity={"type": "Root"})
        assert cloudtrail_plugin.extract_actor(event) == "root"

    def test_aws_service(self, cloudtrail_plugin):
        event = _cloudtrail_event(userIdentity={
            "type": "AWSService",
            "invokedBy": "elasticmapreduce.amazonaws.com",
        })
        assert cloudtrail_plugin.extract_actor(event) == "elasticmapreduce.amazonaws.com"

    def test_fallback_to_arn(self, cloudtrail_plugin):
        event = _cloudtrail_event(userIdentity={
            "type": "FederatedUser",
            "arn": "arn:aws:sts::123:federated-user/alice",
        })
        assert cloudtrail_plugin.extract_actor(event) == "arn:aws:sts::123:federated-user/alice"

    def test_explicit_actor_field_takes_precedence(self, cloudtrail_plugin):
        event = _cloudtrail_event(actor="explicit-actor")
        assert cloudtrail_plugin.extract_actor(event) == "explicit-actor"

    def test_empty_user_identity(self, cloudtrail_plugin):
        event = _cloudtrail_event(userIdentity={})
        assert cloudtrail_plugin.extract_actor(event) == ""


# ===========================================================================
# CloudTrailPlugin — generate_event_section
# ===========================================================================
class TestCloudTrailGenerateEventSection:
    def test_contains_event_fields(self, cloudtrail_plugin):
        event = _cloudtrail_event()
        section = cloudtrail_plugin.generate_event_section(event)
        assert "ConsoleLogin" in section
        assert "signin.amazonaws.com" in section
        assert "test-user" in section
        assert "203.0.113.1" in section
        assert "us-east-1" in section
        assert "123456789012" in section

    def test_returns_html(self, cloudtrail_plugin):
        section = cloudtrail_plugin.generate_event_section(_cloudtrail_event())
        assert "<div" in section
        assert "section-title" in section

    def test_missing_fields_default_to_unknown(self, cloudtrail_plugin):
        section = cloudtrail_plugin.generate_event_section({})
        assert "unknown" in section

    def test_xss_escaped(self, cloudtrail_plugin):
        event = _cloudtrail_event(eventName="<script>alert(1)</script>")
        section = cloudtrail_plugin.generate_event_section(event)
        assert "<script>" not in section
        assert "&lt;script&gt;" in section


# ===========================================================================
# CloudTrailPlugin — get_event_details
# ===========================================================================
class TestCloudTrailGetEventDetails:
    def test_all_keys_present(self, cloudtrail_plugin):
        details = cloudtrail_plugin.get_event_details(_cloudtrail_event())
        expected_keys = {
            "eventType", "actor", "sourceIPAddress", "eventName",
            "target", "accountId", "region", "eventTime",
            "userIdentityType", "userIdentityPrincipalId",
            "userIdentityAccountId", "userIdentityAccessKeyId",
            "eventSource", "resources", "userAgent",
            "requestParameters", "responseElements",
            "errorCode", "errorMessage",
        }
        assert expected_keys.issubset(details.keys())

    def test_actor_extracted(self, cloudtrail_plugin):
        details = cloudtrail_plugin.get_event_details(_cloudtrail_event())
        assert details["actor"] == "test-user"

    def test_target_from_request_parameters(self, cloudtrail_plugin):
        details = cloudtrail_plugin.get_event_details(_cloudtrail_event())
        assert details["target"] == "admin-role"

    def test_none_event_returns_defaults(self, cloudtrail_plugin):
        details = cloudtrail_plugin.get_event_details(None)
        assert details["eventType"] == "unknown"
        assert details["actor"] == "unknown"

    def test_empty_event_returns_unknowns(self, cloudtrail_plugin):
        details = cloudtrail_plugin.get_event_details({})
        assert details["eventType"] == "unknown"
        assert details["sourceIPAddress"] == "unknown"


# ===========================================================================
# GenericEventPlugin — identity & metadata
# ===========================================================================
class TestGenericPluginIdentity:
    def test_plugin_name(self, generic_plugin):
        assert generic_plugin.get_plugin_name() == "generic"

    def test_event_type(self, generic_plugin):
        assert generic_plugin.get_event_type() == "Generic"

    def test_can_process_any_event(self, generic_plugin):
        assert generic_plugin.can_process_event({}) is True
        assert generic_plugin.can_process_event({"anything": True}) is True
        assert generic_plugin.can_process_event(_cloudtrail_event()) is True


# ===========================================================================
# GenericEventPlugin — extract_actor
# ===========================================================================
class TestGenericExtractActor:
    def test_explicit_actor(self, generic_plugin):
        assert generic_plugin.extract_actor({"actor": "user1"}) == "user1"

    def test_fallback_to_arn(self, generic_plugin):
        event = {"userIdentity": {"arn": "arn:aws:iam::123:user/bob"}}
        assert generic_plugin.extract_actor(event) == "arn:aws:iam::123:user/bob"

    def test_fallback_to_username(self, generic_plugin):
        event = {"userIdentity": {"userName": "alice"}}
        assert generic_plugin.extract_actor(event) == "alice"

    def test_fallback_to_identity_type(self, generic_plugin):
        event = {"userIdentity": {"type": "Root"}}
        assert generic_plugin.extract_actor(event) == "Root"

    def test_fallback_to_source_ip(self, generic_plugin):
        event = {"sourceIPAddress": "10.0.0.1"}
        assert generic_plugin.extract_actor(event) == "10.0.0.1"

    def test_fallback_to_source(self, generic_plugin):
        event = {"source": "my-service"}
        assert generic_plugin.extract_actor(event) == "my-service"

    def test_ultimate_fallback_unknown(self, generic_plugin):
        assert generic_plugin.extract_actor({}) == "unknown"

    def test_actor_field_takes_precedence(self, generic_plugin):
        event = {"actor": "explicit", "userIdentity": {"arn": "ignored"}}
        assert generic_plugin.extract_actor(event) == "explicit"


# ===========================================================================
# GenericEventPlugin — generate_event_section
# ===========================================================================
class TestGenericGenerateEventSection:
    def test_contains_event_fields(self, generic_plugin):
        event = _generic_event(actor="user1")
        section = generic_plugin.generate_event_section(event)
        assert "user1" in section
        assert "192.168.1.1" in section
        assert "eu-west-1" in section

    def test_returns_html(self, generic_plugin):
        section = generic_plugin.generate_event_section(_generic_event())
        assert "<div" in section
        assert "section-title" in section

    def test_missing_fields_default_to_unknown(self, generic_plugin):
        section = generic_plugin.generate_event_section({})
        assert "unknown" in section

    def test_xss_escaped(self, generic_plugin):
        event = _generic_event(eventType="<img onerror=alert(1)>")
        section = generic_plugin.generate_event_section(event)
        assert "<img" not in section
        assert "&lt;img" in section


# ===========================================================================
# GenericEventPlugin — get_event_details
# ===========================================================================
class TestGenericGetEventDetails:
    def test_all_keys_present(self, generic_plugin):
        details = generic_plugin.get_event_details(_generic_event())
        expected_keys = {
            "eventType", "actor", "sourceIPAddress", "eventTime",
            "awsRegion", "recipientAccountId", "userAgent",
            "requestParameters", "responseElements",
            "errorCode", "errorMessage",
        }
        assert expected_keys == set(details.keys())

    def test_actor_extracted(self, generic_plugin):
        details = generic_plugin.get_event_details(_generic_event(actor="user1"))
        assert details["actor"] == "user1"

    def test_empty_event_returns_unknowns(self, generic_plugin):
        details = generic_plugin.get_event_details({})
        assert details["eventType"] == "unknown"
        assert details["actor"] == "unknown"


# ===========================================================================
# PluginConfig
# ===========================================================================
class TestPluginConfig:
    def test_default_all_enabled(self):
        with patch.dict(os.environ, {}, clear=True):
            config = PluginConfig()
            assert config.is_plugin_enabled("cloudtrail") is True
            assert config.is_plugin_enabled("generic") is True
            assert config.get_enabled_plugins() == []

    def test_explicit_enabled_list(self):
        with patch.dict(os.environ, {"ENABLED_PLUGINS": '["cloudtrail"]'}):
            config = PluginConfig()
            assert config.is_plugin_enabled("cloudtrail") is True
            assert config.is_plugin_enabled("generic") is False
            assert config.get_enabled_plugins() == ["cloudtrail"]

    def test_invalid_json_falls_back_to_empty(self):
        with patch.dict(os.environ, {"ENABLED_PLUGINS": "not-json"}):
            config = PluginConfig()
            assert config.is_plugin_enabled("anything") is True

    def test_non_array_json_falls_back_to_empty(self):
        with patch.dict(os.environ, {"ENABLED_PLUGINS": '{"key": "value"}'}):
            config = PluginConfig()
            assert config.is_plugin_enabled("anything") is True

    def test_get_plugin_config_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            config = PluginConfig()
            assert config.get_plugin_config("cloudtrail") == {}

    def test_enabled_plugins_returns_copy(self):
        with patch.dict(os.environ, {"ENABLED_PLUGINS": '["a","b"]'}):
            config = PluginConfig()
            copy = config.get_enabled_plugins()
            copy.append("c")
            assert config.get_enabled_plugins() == ["a", "b"]


# ===========================================================================
# Abstract base class contract
# ===========================================================================
class TestEventSourcePluginABC:
    def test_cannot_instantiate_base(self):
        with pytest.raises(TypeError):
            EventSourcePlugin()

    def test_cloudtrail_is_subclass(self):
        assert issubclass(CloudTrailPlugin, EventSourcePlugin)

    def test_generic_is_subclass(self):
        assert issubclass(GenericEventPlugin, EventSourcePlugin)