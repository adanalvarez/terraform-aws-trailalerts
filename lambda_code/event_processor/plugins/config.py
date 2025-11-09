"""
Plugin configuration for the Sigma Event Processor.
This module manages configuration for plugins.
"""
import os
import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger()

class PluginConfig:
    """Configuration manager for plugins."""
    
    def __init__(self):
        """Initialize the plugin configuration."""
        self._enabled_plugins: List[str] = []
        self._plugin_configs: Dict[str, Dict[str, Any]] = {}
        self._load_config()
    
    def _load_config(self) -> None:
        """Load plugin configuration from environment variables."""
        # Load enabled plugins
        enabled_plugins_str = os.environ.get("ENABLED_PLUGINS", "[]")
        try:
            self._enabled_plugins = json.loads(enabled_plugins_str)
            if not isinstance(self._enabled_plugins, list):
                logger.warning("ENABLED_PLUGINS must be a JSON array, using empty list")
                self._enabled_plugins = []
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in ENABLED_PLUGINS: {enabled_plugins_str}, using empty list")
            self._enabled_plugins = []
        
        # Log enabled plugins
        if self._enabled_plugins:
            logger.info(f"Enabled plugins: {', '.join(self._enabled_plugins)}")
        else:
            logger.info("No plugins explicitly enabled, all plugins will be enabled")
    
    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """
        Check if a plugin is enabled.
        
        Args:
            plugin_name: The name of the plugin to check
            
        Returns:
            bool: True if the plugin is enabled
        """
        # If no plugins are explicitly enabled, all plugins are enabled
        if not self._enabled_plugins:
            return True
        
        return plugin_name in self._enabled_plugins
    
    def get_plugin_config(self, plugin_name: str) -> Dict[str, Any]:
        """
        Get the configuration for a plugin.
        
        Args:
            plugin_name: The name of the plugin to get configuration for
            
        Returns:
            Dict[str, Any]: The plugin configuration
        """
        return self._plugin_configs.get(plugin_name, {})
    
    def get_enabled_plugins(self) -> List[str]:
        """
        Get the list of enabled plugin names.
        
        Returns:
            List[str]: List of enabled plugin names
        """
        return self._enabled_plugins.copy() 