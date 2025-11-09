"""
Plugin system for the Sigma Event Processor.

This package provides a plugin system for processing events from different sources.
Each plugin is responsible for handling a specific type of event and providing
consistent interfaces for event processing, actor extraction, and HTML generation.
"""

from plugins.base import EventSourcePlugin
from plugins.registry import PluginRegistry
from plugins.config import PluginConfig
from plugins.cloudtrail import CloudTrailPlugin
from plugins.generic import GenericEventPlugin

__all__ = [
    'EventSourcePlugin',
    'PluginRegistry',
    'PluginConfig',
    'CloudTrailPlugin',
    'GenericEventPlugin'
] 