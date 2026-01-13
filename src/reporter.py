#!/usr/bin/env python3
"""
Reporting and Logging Module
Generates detection reports and manages event logs
"""

import json
import csv
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate and export monitoring reports"""
    
    def __init__(self, output_dir='reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logs_dir = Path('logs')
        self.logs_dir.mkdir(exist_ok=True)
    
    def generate_report(self, processes, services, alerts, timestamp):
        """Generate comprehensive monitoring report"""
        report = {
            'timestamp': timestamp.isoformat(),
            'summary': {
                'total_processes': len(processes),
                'total_services': len(services),
                'total_alerts': len(alerts),
                'alert_severity': self._count_severity(alerts)
            },
            'alerts': alerts,
            'top_processes': processes[:10] if processes else []
        }
        
        # Export as JSON
        json_file = self.output_dir / f"detection_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report exported: {json_file}")
        except Exception as e:
            logger.error(f"Error exporting report: {e}")
        
        # Log events to CSV
        self._log_to_csv(processes, timestamp)
        
        return report
    
    def _count_severity(self, alerts):
        """Count alerts by severity"""
        severity_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for alert in alerts:
            severity = alert.get('severity', 'LOW')
            if severity in severity_count:
                severity_count[severity] += 1
        return severity_count
    
    def _log_to_csv(self, processes, timestamp):
        """Log process information to CSV"""
        log_file = self.logs_dir / 'monitoring_logs.csv'
        try:
            with open(log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                for proc in processes[:5]:  # Log sample
                    writer.writerow([
                        timestamp.isoformat(),
                        proc.get('pid'),
                        proc.get('name'),
                        proc.get('path', 'N/A')
                    ])
        except Exception as e:
            logger.error(f"Error logging to CSV: {e}")
