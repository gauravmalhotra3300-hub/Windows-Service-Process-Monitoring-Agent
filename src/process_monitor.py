#!/usr/bin/env python3
"""
Process Enumeration and Analysis Module
Detects suspicious parent-child relationships and process chains
"""

import psutil
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

class ProcessMonitor:
    """Monitor and analyze Windows processes"""
    
    def __init__(self):
        self.suspicious_parents = {
            'cmd.exe': {'winword.exe', 'excel.exe', 'acrobat.exe'},
            'powershell.exe': {'winword.exe', 'excel.exe'},
            'cscript.exe': {'explorer.exe', 'svchost.exe'},
            'wscript.exe': {'explorer.exe', 'svchost.exe'},
        }
        self.system_critical = {
            'system', 'svchost.exe', 'csrss.exe', 'services.exe',
            'lsass.exe', 'explorer.exe', 'kernel32.dll'
        }
        
    def enumerate_processes(self):
        """Enumerate all active processes"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'ppid': proc.info['ppid'],
                        'name': proc.info['name'],
                        'path': proc.info['exe'],
                        'timestamp': datetime.now().isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.error(f"Error enumerating processes: {e}")
        
        return processes
    
    def get_process_tree(self):
        """Build parent-child process tree"""
        tree = defaultdict(list)
        try:
            for proc in psutil.process_iter(['pid', 'ppid']):
                try:
                    tree[proc.info['ppid']].append(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.error(f"Error building process tree: {e}")
        
        return tree
    
    def detect_suspicious_chains(self):
        """Detect suspicious parent-child process relationships"""
        suspicious = []
        try:
            for proc in psutil.process_iter(['pid', 'ppid', 'name']):
                try:
                    ppid = proc.info['ppid']
                    current_name = proc.info['name'].lower()
                    
                    if ppid:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name().lower()
                        
                        if parent_name in self.suspicious_parents:
                            if current_name in self.suspicious_parents[parent_name]:
                                suspicious.append({
                                    'parent_pid': ppid,
                                    'parent_name': parent_name,
                                    'child_pid': proc.info['pid'],
                                    'child_name': current_name,
                                    'risk_level': 'HIGH'
                                })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.error(f"Error detecting suspicious chains: {e}")
        
        return suspicious
    
    def detect_unauthorized(self, whitelist_manager):
        """Detect unauthorized/unknown processes"""
        unauthorized = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    name = proc.info['name']
                    path = proc.info['exe']
                    
                    # Check if process is in whitelist
                    if not whitelist_manager.is_whitelisted(name, path):
                        unauthorized.append({
                            'pid': proc.info['pid'],
                            'name': name,
                            'path': path,
                            'timestamp': datetime.now().isoformat()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.error(f"Error detecting unauthorized processes: {e}")
        
        return unauthorized
