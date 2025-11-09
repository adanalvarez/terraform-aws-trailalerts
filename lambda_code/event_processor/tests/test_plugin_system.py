import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add the parent directory to sys.path to enable module imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.base import EventSourcePlugin
from plugins.registry import PluginRegistry
from plugins.cloudtrail import CloudTrailPlugin
from plugins.generic import GenericEventPlugin

class TestPluginSystem(unittest.TestCase):
    """Test cases for the plugin system"""
    
    def setUp(self):
        """Set up test fixtures, if any."""
        self.registry = PluginRegistry()
        self.cloudtrail_plugin = CloudTrailPlugin()
        self.generic_plugin = GenericEventPlugin()
    
    def test_plugin_registration(self):
        """Test plugin registration"""
        # Register plugins
        self.registry.register_plugin(self.cloudtrail_plugin)
        self.registry.register_plugin(self.generic_plugin)
        
        # Check if plugins are registered
        self.assertEqual(len(self.registry.get_all_plugins()), 2)
        self.assertEqual(self.registry.get_plugin_by_name("cloudtrail"), self.cloudtrail_plugin)
        self.assertEqual(self.registry.get_plugin_by_name("generic"), self.generic_plugin)
    
    def test_get_plugin_for_cloudtrail_event(self):
        """Test getting the appropriate plugin for a CloudTrail event"""
        # Register plugins
        self.registry.register_plugin(self.cloudtrail_plugin)
        self.registry.register_plugin(self.generic_plugin)
        
        # Create a sample CloudTrail event
        cloudtrail_event = {
            "sigmaEventSource": "CloudTrail",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/test-user"
            }
        }
        
        # Get plugin for CloudTrail event
        plugin = self.registry.get_plugin_for_event(cloudtrail_event)
        
        # Verify CloudTrail plugin is returned
        self.assertEqual(plugin, self.cloudtrail_plugin)
        self.assertEqual(plugin.get_plugin_name(), "cloudtrail")
    
    def test_get_plugin_for_generic_event(self):
        """Test getting the appropriate plugin for a generic event"""
        # Register plugins
        self.registry.register_plugin(self.cloudtrail_plugin)
        self.registry.register_plugin(self.generic_plugin)
        
        # Create a sample generic event (not CloudTrail)
        generic_event = {
            "eventType": "CustomEvent",
            "sourceIPAddress": "192.168.1.1",
            "actor": "user1"
        }
        
        # Get plugin for generic event
        plugin = self.registry.get_plugin_for_event(generic_event)
        
        # Verify generic plugin is returned
        self.assertEqual(plugin, self.generic_plugin)
        self.assertEqual(plugin.get_plugin_name(), "generic")
    
    def test_fallback_to_generic_plugin(self):
        """Test that the system falls back to the generic plugin when no other plugins match"""
        # Register plugins
        self.registry.register_plugin(self.cloudtrail_plugin)
        self.registry.register_plugin(self.generic_plugin)
        
        # Create an unknown event type
        unknown_event = {
            "type": "UnknownType",
            "data": "test"
        }
        
        # Get plugin for unknown event
        plugin = self.registry.get_plugin_for_event(unknown_event)
        
        # Verify generic plugin is returned as fallback
        self.assertEqual(plugin, self.generic_plugin)
        self.assertEqual(plugin.get_plugin_name(), "generic")
    
    def test_cloudtrail_plugin_extract_actor(self):
        """Test the actor extraction functionality in CloudTrail plugin"""
        # Create a sample event with IAM user
        iam_user_event = {
            "userIdentity": {
                "type": "IAMUser",
                "userName": "test-user",
                "arn": "arn:aws:iam::123456789012:user/test-user"
            }
        }
        
        # Test actor extraction
        actor = self.cloudtrail_plugin.extract_actor(iam_user_event)
        self.assertEqual(actor, "test-user")
        
        # Create a sample event with assumed role
        assumed_role_event = {
            "userIdentity": {
                "type": "AssumedRole",
                "arn": "arn:aws:iam::123456789012:role/test-role"
            }
        }
        
        # Test actor extraction
        actor = self.cloudtrail_plugin.extract_actor(assumed_role_event)
        self.assertEqual(actor, "arn:aws:iam::123456789012:role/test-role")
        
        # Create a sample event with root user
        root_user_event = {
            "userIdentity": {
                "type": "Root"
            }
        }
        
        # Test actor extraction
        actor = self.cloudtrail_plugin.extract_actor(root_user_event)
        self.assertEqual(actor, "root")

if __name__ == '__main__':
    unittest.main()