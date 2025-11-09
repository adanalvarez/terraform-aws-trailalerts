"""
Base plugin interface for the Sigma Event Processor.
All event source plugins must implement this interface.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class EventSourcePlugin(ABC):
    """Base class for event source plugins."""
    
    @abstractmethod
    def get_plugin_name(self) -> str:
        """
        Get the name of the plugin.
        
        Returns:
            str: The plugin name
        """
        pass
    
    @abstractmethod
    def get_event_type(self) -> str:
        """
        Get the event type this plugin handles.
        
        Returns:
            str: The event type
        """
        pass
    
    @abstractmethod
    def can_process_event(self, event: Dict[str, Any]) -> bool:
        """
        Check if this plugin can process the given event.
        
        Args:
            event: The event to check
            
        Returns:
            bool: True if this plugin can process the event
        """
        pass
    
    @abstractmethod
    def extract_actor(self, event: Dict[str, Any]) -> str:
        """
        Extract the actor from an event.
        
        Args:
            event: The event
            
        Returns:
            str: The actor identifier
        """
        pass
    
    @abstractmethod
    def generate_event_section(self, event: Dict[str, Any]) -> str:
        """
        Generate an HTML section for an event.
        
        Args:
            event: The event
            
        Returns:
            str: HTML section for the event
        """
        pass
    
    @abstractmethod
    def get_event_details(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract relevant details from an event.
        
        Args:
            event: The event
            
        Returns:
            Dict[str, Any]: Dictionary containing event details
        """
        pass 