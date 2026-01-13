#!/usr/bin/env python3
"""
Windows Service & Process Monitoring Agent
Main monitoring orchestrator
"""

import sys
import os
import argparse
import logging
from datetime import datetime

try:
    import psutil
    from process_monitor import ProcessMonitor
    from service_audit import ServiceAuditor
    from whitelist_manager import WhitelistManager
    from anomaly_detector import AnomalyDetector
    from reporter import ReportGenerator
except ImportError as e:
    print(f"Error: Missing dependencies. Please run: pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MonitoringAgent:
    """Main monitoring agent orchestrator"""
    
    def __init__(self, config_path='config/'):
        self.config_path = config_path
        self.process_monitor = ProcessMonitor()
        self.service_auditor = ServiceAuditor()
        self.whitelist_manager = WhitelistManager(f"{config_path}whitelist.json")
        self.anomaly_detector = AnomalyDetector(f"{config_path}detection_rules.yaml")
        self.reporter = ReportGenerator()
        self.alerts = []
        
    def start_monitoring(self, continuous=False, interval=5):
        """Start the monitoring process"""
        logger.info("=" * 60)
        logger.info("Windows Service & Process Monitoring Agent Started")
        logger.info(f"Timestamp: {datetime.now()}")
        logger.info("=" * 60)
        
        if continuous:
            while True:
                self.run_scan()
                logger.info(f"Sleeping for {interval} seconds...")
                import time
                time.sleep(interval)
        else:
            self.run_scan()
            
    def run_scan(self):
        """Execute a single monitoring scan"""
        logger.info("\n[*] Starting scan cycle...")
        
        # 1. Enumerate processes
        logger.info("[1] Enumerating active processes...")
        processes = self.process_monitor.enumerate_processes()
        logger.info(f"    Found {len(processes)} active processes")
        
        # 2. Analyze parent-child relationships
        logger.info("[2] Analyzing process tree...")
        suspicious_chains = self.process_monitor.detect_suspicious_chains()
        if suspicious_chains:
            logger.warning(f"    Found {len(suspicious_chains)} suspicious process chains")
            for chain in suspicious_chains:
                self.alerts.append({
                    'type': 'suspicious_parent_child',
                    'severity': 'HIGH',
                    'details': chain
                })
        
        # 3. Audit startup services
        logger.info("[3] Auditing startup services...")
        services = self.service_auditor.audit_services()
        logger.info(f"    Found {len(services)} services")
        
        # 4. Detect unauthorized processes
        logger.info("[4] Checking for unauthorized processes...")
        unauthorized = self.process_monitor.detect_unauthorized(self.whitelist_manager)
        if unauthorized:
            logger.warning(f"    Found {len(unauthorized)} unauthorized processes")
            for proc in unauthorized:
                self.alerts.append({
                    'type': 'unauthorized_process',
                    'severity': 'MEDIUM',
                    'details': proc
                })
        
        # 5. Generate alerts and report
        logger.info("[5] Generating report...")
        self.reporter.generate_report(
            processes=processes,
            services=services,
            alerts=self.alerts,
            timestamp=datetime.now()
        )
        
        logger.info(f"\n[+] Scan complete. {len(self.alerts)} alerts detected.")
        
def main():
    parser = argparse.ArgumentParser(
        description='Windows Service & Process Monitoring Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python monitor_agent.py                    # Run single scan
  python monitor_agent.py --continuous      # Run continuous monitoring
  python monitor_agent.py -c -i 10           # Continuous monitoring every 10 seconds
        """
    )
    
    parser.add_argument(
        '-c', '--continuous',
        action='store_true',
        help='Run continuous monitoring'
    )
    parser.add_argument(
        '-i', '--interval',
        type=int,
        default=5,
        help='Monitoring interval in seconds (default: 5)'
    )
    parser.add_argument(
        '--config',
        default='config/',
        help='Path to config directory'
    )
    
    args = parser.parse_args()
    
    try:
        agent = MonitoringAgent(config_path=args.config)
        agent.start_monitoring(continuous=args.continuous, interval=args.interval)
    except KeyboardInterrupt:
        logger.info("\nMonitoring stopped by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
