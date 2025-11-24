"""
Key Logger Module
Logs key-related events (RSA generation, Room Key reception, etc.) for audit purposes.
"""

import json
import os
from datetime import datetime
from src.common.logger_config import setup_logger

log = setup_logger(__name__)


class KeyLogger:
    """Logs cryptographic key events for audit and debugging"""
    
    def __init__(self, log_file="client_key_log.json"):
        self.log_file = log_file
        self._ensure_log_file()
    
    def _ensure_log_file(self):
        """Create log file if it doesn't exist"""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                json.dump([], f)
    
    def log_event(self, event_type, description, key_data=None, context=None):
        """
        Log a key-related event
        
        Args:
            event_type: Type of event (e.g., 'RSA_GENERATION', 'ROOM_KEY_RECEIVED')
            description: Human-readable description
            key_data: Dict with key information (parts of the key, hash, etc.)
            context: Additional context (room_id, username, etc.)
        """
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'description': description,
            'key_data': key_data or {},
            'context': context or {}
        }
        
        try:
            # Read existing logs
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
            
            # Append new event
            logs.append(event)
            
            # Write back
            with open(self.log_file, 'w') as f:
                json.dump(logs, f, indent=2)
            
            log.debug(f"Key event logged: {event_type}")
        except Exception as e:
            log.error(f"Failed to log key event: {e}")
    
    def get_logs(self, limit=None):
        """
        Retrieve logged events
        
        Args:
            limit: Maximum number of events to return (most recent first)
        
        Returns:
            List of event dicts
        """
        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
            
            # Return most recent first
            logs.reverse()
            
            if limit:
                return logs[:limit]
            return logs
        except Exception as e:
            log.error(f"Failed to read key logs: {e}")
            return []
    
    def clear_logs(self):
        """Clear all logged events"""
        try:
            with open(self.log_file, 'w') as f:
                json.dump([], f)
            log.info("Key logs cleared")
        except Exception as e:
            log.error(f"Failed to clear key logs: {e}")
