"""
Plugin registry for the Sigma Event Processor.
This module manages all available event source plugins.
"""
import os
import importlib
import logging
from typing import Dict, List, Optional, Any

from plugins.base import EventSourcePlugin

logger = logging.getLogger()

class PluginRegistry:
    """Registry for managing event source plugins."""
    
    def __init__(self):
        """Initialize the plugin registry."""
        self.plugins = {}
    
    def register_plugin(self, plugin: EventSourcePlugin) -> None:
        """
        Register a new plugin.
        
        Args:
            plugin: The plugin to register
        """
        plugin_name = plugin.get_plugin_name()
        self.plugins[plugin_name] = plugin
        logger.info(f"Registered plugin: {plugin_name}")
    
    def get_plugin_for_event(self, event: Dict[str, Any]) -> Optional[EventSourcePlugin]:
        """
        Find the appropriate plugin for an event.
        
        Args:
            event: The event to find a plugin for
            
        Returns:
            Optional[EventSourcePlugin]: The plugin that can process the event, or None if no plugin is found
        """
        for plugin in self.plugins.values():
            if plugin.can_process_event(event):
                return plugin
        return None
    
    def get_all_plugins(self) -> List[EventSourcePlugin]:
        """
        Get all registered plugins.
        
        Returns:
            List[EventSourcePlugin]: List of all registered plugins
        """
        return list(self.plugins.values())
    
    def get_plugin_by_name(self, plugin_name: str) -> Optional[EventSourcePlugin]:
        """
        Get a plugin by name.
        
        Args:
            plugin_name: The name of the plugin to get
            
        Returns:
            Optional[EventSourcePlugin]: The plugin with the given name, or None if not found
        """
        return self.plugins.get(plugin_name)
    
    @classmethod
    def discover_plugins(cls) -> List[EventSourcePlugin]:
        """
        Discover and load plugins from the plugins directory.
        
        Returns:
            List[EventSourcePlugin]: List of discovered plugins
        """
        plugins = []
        
        # Get the plugins directory
        plugins_dir = os.path.join(os.path.dirname(__file__))
        
        # Iterate through Python files in the plugins directory
        for filename in os.listdir(plugins_dir):
            if filename.endswith(".py") and not filename.startswith("__") and filename != "base.py" and filename != "registry.py":
                module_name = filename[:-3]
                try:
                    # Import the module
                    module = importlib.import_module(f"plugins.{module_name}")
                    
                    # Look for plugin classes
                    for item_name in dir(module):
                        item = getattr(module, item_name)
                        if isinstance(item, type) and issubclass(item, EventSourcePlugin) and item != EventSourcePlugin:
                            # Instantiate the plugin
                            plugin = item()
                            plugins.append(plugin)
                            logger.info(f"Discovered plugin: {plugin.get_plugin_name()}")
                except Exception as e:
                    logger.error(f"Error loading plugin {module_name}: {str(e)}")
        
        return plugins 