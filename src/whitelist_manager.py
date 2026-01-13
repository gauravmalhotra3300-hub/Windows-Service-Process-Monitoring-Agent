#!/usr/bin/env python3
"""
Whitelist/Blacklist Management Module
"""

import json
import logging

logger = logging.getLogger(__name__)

class WhitelistManager:
    """Manage whitelisted and blacklisted processes"""
    
    def __init__(self, whitelist_file=None):
        self.whitelist = set()
        self.blacklist = set()
        
        # Default safe processes
        self.whitelist.update([
            'explorer.exe', 'svchost.exe', 'csrss.exe', 'services.exe',
            'lsass.exe', 'wininit.exe', 'winlogon.exe', 'dwm.exe',
            'searchindexer.exe', 'chrome.exe', 'firefox.exe', 'notepad.exe'
        ])
        
        if whitelist_file:
            self._load_whitelist(whitelist_file)
    
    def _load_whitelist(self, filename):
        """Load whitelist from JSON file"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                self.whitelist.update(data.get('processes', []))
        except FileNotFoundError:
            logger.warning(f"Whitelist file not found: {filename}")
        except Exception as e:
            logger.error(f"Error loading whitelist: {e}")
    
    def is_whitelisted(self, process_name, path=None):
        """Check if process is whitelisted"""
        return process_name.lower() in self.whitelist
    
    def add_to_whitelist(self, process_name):
        """Add process to whitelist"""
        self.whitelist.add(process_name.lower())
        logger.info(f"Added to whitelist: {process_name}")
    
    def add_to_blacklist(self, process_name):
        """Add process to blacklist"""
        self.blacklist.add(process_name.lower())
        logger.info(f"Added to blacklist: {process_name}")
