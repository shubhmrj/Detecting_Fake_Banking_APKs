"""
Hackathon Solution: Real-time APK Monitoring System
Provides continuous monitoring, threat detection, and automated response
"""

import os
import sys
import time
import sqlite3
import threading
from pathlib import Path
from datetime import datetime
from flask import Flask, jsonify
from flask_cors import CORS
import schedule

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.archive_development_files.hackathon_repository_scanner import HackathonRepositoryScanner

class HackathonRealTimeMonitor:
    """
    Real-time monitoring system for continuous APK threat detection
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.monitor_db = self.base_dir / "data" / "hackathon_monitor.db"
        self.scanner = HackathonRepositoryScanner()
        
        # Monitoring configuration
        self.monitoring_active = False
        self.scan_interval_minutes = 30  # Scan every 30 minutes
        self.alert_threshold = 40  # Risk score threshold for alerts
        
        # Setup monitoring database
        self.setup_monitoring_database()
        
        # Setup Flask app for dashboard
        self.app = Flask(__name__)
        CORS(self.app)
        self.setup_dashboard_routes()
        
        print("[OK] Real-time Monitor initialized")
    
    def setup_monitoring_database(self):
        """Setup monitoring database"""
        conn = sqlite3.connect(self.monitor_db)
        cursor = conn.cursor()
        
        # Real-time alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS realtime_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                apk_name TEXT,
                risk_score INTEGER,
                description TEXT,
                status TEXT DEFAULT 'active',
                response_action TEXT,
                resolved_at TIMESTAMP
            )
        ''')
        
        # Monitoring sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                session_end TIMESTAMP,
                scans_performed INTEGER DEFAULT 0,
                threats_detected INTEGER DEFAULT 0,
                alerts_generated INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # System health table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_health (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                check_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cpu_usage REAL,
                memory_usage REAL,
                disk_usage REAL,
                scanner_status TEXT,
                api_status TEXT,
                database_status TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[OK] Monitoring database initialized")
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        print("\n" + "=" * 60)
        print("STARTING REAL-TIME APK MONITORING")
        print("=" * 60)
        
        self.monitoring_active = True
        
        # Start monitoring session
        session_id = self.start_monitoring_session()
        
        # Schedule periodic scans
        schedule.every(self.scan_interval_minutes).minutes.do(self.perform_scheduled_scan)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        
        # Start health check thread
        health_thread = threading.Thread(target=self.health_check_loop, daemon=True)
        health_thread.start()
        
        print(f"[OK] Real-time monitoring started (Session ID: {session_id})")
        print(f"[OK] Scan interval: {self.scan_interval_minutes} minutes")
        print(f"[OK] Alert threshold: {self.alert_threshold} risk score")
        
        return session_id
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Run scheduled tasks
                schedule.run_pending()
                
                # Check for new threats
                self.check_for_new_threats()
                
                # Process pending alerts
                self.process_pending_alerts()
                
                # Sleep for 60 seconds
                time.sleep(60)
                
            except Exception as e:
                print(f"[ERROR] Monitoring loop error: {str(e)}")
                time.sleep(60)
    
    def health_check_loop(self):
        """System health monitoring loop"""
        while self.monitoring_active:
            try:
                # Perform health checks
                health_status = self.perform_health_check()
                
                # Record health status
                self.record_health_status(health_status)
                
                # Sleep for 5 minutes
                time.sleep(300)
                
            except Exception as e:
                print(f"[ERROR] Health check error: {str(e)}")
                time.sleep(300)
    
    def perform_scheduled_scan(self):
        """Perform scheduled repository scan"""
        print(f"\n[SCHEDULED SCAN] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            # Run repository scan
            scan_results = self.scanner.scan_apk_repositories()
            
            # Process scan results for real-time alerts
            self.process_scan_results(scan_results)
            
            # Update monitoring session
            self.update_monitoring_session(scan_results)
            
            print(f"[OK] Scheduled scan completed")
            
        except Exception as e:
            print(f"[ERROR] Scheduled scan failed: {str(e)}")
            self.create_alert("SCAN_FAILURE", "HIGH", f"Scheduled scan failed: {str(e)}")
    
    def process_scan_results(self, scan_results):
        """Process scan results and generate alerts"""
        if scan_results['suspicious_apps'] > 0:
            self.create_alert(
                "SUSPICIOUS_APPS_DETECTED",
                "HIGH" if scan_results['suspicious_apps'] > 5 else "MEDIUM",
                f"Detected {scan_results['suspicious_apps']} suspicious APKs in latest scan"
            )
        
        if scan_results['threats_blocked'] > 0:
            self.create_alert(
                "THREATS_BLOCKED",
                "HIGH",
                f"Automatically blocked {scan_results['threats_blocked']} threats"
            )
    
    def check_for_new_threats(self):
        """Check for new threats in the system"""
        try:
            # Check scanner database for recent high-risk APKs
            scanner_conn = sqlite3.connect(self.scanner.scanner_db)
            cursor = scanner_conn.cursor()
            
            # Get APKs scanned in last hour with high risk
            cursor.execute('''
                SELECT apk_name, risk_score, classification
                FROM scanned_apks 
                WHERE scan_timestamp > datetime('now', '-1 hour')
                AND risk_score >= ?
                AND is_suspicious = 1
            ''', (self.alert_threshold,))
            
            new_threats = cursor.fetchall()
            scanner_conn.close()
            
            # Generate alerts for new threats
            for threat in new_threats:
                apk_name, risk_score, classification = threat
                self.create_alert(
                    "NEW_THREAT_DETECTED",
                    "HIGH" if risk_score >= 70 else "MEDIUM",
                    f"New threat detected: {apk_name} (Risk: {risk_score}, Class: {classification})",
                    apk_name=apk_name,
                    risk_score=risk_score
                )
            
        except Exception as e:
            print(f"[ERROR] Threat check failed: {str(e)}")
    
    def create_alert(self, alert_type, severity, description, apk_name=None, risk_score=None):
        """Create real-time alert"""
        conn = sqlite3.connect(self.monitor_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO realtime_alerts 
            (alert_type, severity, apk_name, risk_score, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_type, severity, apk_name, risk_score, description))
        
        conn.commit()
        conn.close()
        
        # Print alert to console
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[ALERT {severity}] {timestamp} - {description}")
        
        # Trigger automated response if needed
        if severity == "HIGH":
            self.trigger_automated_response(alert_type, description)
    
    def trigger_automated_response(self, alert_type, description):
        """Trigger automated response for high-severity alerts"""
        response_actions = []
        
        if alert_type == "NEW_THREAT_DETECTED":
            response_actions.append("Quarantine APK")
            response_actions.append("Block distribution")
            response_actions.append("Notify security team")
        
        elif alert_type == "SUSPICIOUS_APPS_DETECTED":
            response_actions.append("Increase scan frequency")
            response_actions.append("Enhanced monitoring")
        
        elif alert_type == "SCAN_FAILURE":
            response_actions.append("Restart scanner")
            response_actions.append("Check system health")
        
        # Execute response actions
        for action in response_actions:
            print(f"[AUTO RESPONSE] {action}")
            # In real implementation, would execute actual response
    
    def process_pending_alerts(self):
        """Process and manage pending alerts"""
        conn = sqlite3.connect(self.monitor_db)
        cursor = conn.cursor()
        
        # Get active alerts older than 1 hour
        cursor.execute('''
            SELECT id, alert_type, severity, description
            FROM realtime_alerts 
            WHERE status = 'active' 
            AND alert_timestamp < datetime('now', '-1 hour')
        ''')
        
        old_alerts = cursor.fetchall()
        
        # Auto-resolve old low-priority alerts
        for alert in old_alerts:
            alert_id, alert_type, severity, description = alert
            
            if severity == "LOW":
                cursor.execute('''
                    UPDATE realtime_alerts 
                    SET status = 'auto_resolved', resolved_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (alert_id,))
        
        conn.commit()
        conn.close()
    
    def perform_health_check(self):
        """Perform system health check"""
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'scanner_status': 'healthy',
            'api_status': 'healthy',
            'database_status': 'healthy',
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_usage': 0.0
        }
        
        try:
            # Check scanner database connectivity
            scanner_conn = sqlite3.connect(self.scanner.scanner_db)
            scanner_conn.execute('SELECT 1')
            scanner_conn.close()
        except:
            health_status['scanner_status'] = 'error'
        
        try:
            # Check monitor database connectivity
            monitor_conn = sqlite3.connect(self.monitor_db)
            monitor_conn.execute('SELECT 1')
            monitor_conn.close()
        except:
            health_status['database_status'] = 'error'
        
        # Simulate system metrics (in real implementation, would use psutil)
        import random
        health_status['cpu_usage'] = random.uniform(10, 80)
        health_status['memory_usage'] = random.uniform(20, 70)
        health_status['disk_usage'] = random.uniform(30, 90)
        
        return health_status
    
    def record_health_status(self, health_status):
        """Record system health status"""
        conn = sqlite3.connect(self.monitor_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO system_health 
            (cpu_usage, memory_usage, disk_usage, scanner_status, api_status, database_status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            health_status['cpu_usage'],
            health_status['memory_usage'], 
            health_status['disk_usage'],
            health_status['scanner_status'],
            health_status['api_status'],
            health_status['database_status']
        ))
        
        conn.commit()
        conn.close()
    
    def start_monitoring_session(self):
        """Start new monitoring session"""
        conn = sqlite3.connect(self.monitor_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO monitoring_sessions (status)
            VALUES ('active')
        ''')
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return session_id
    
    def update_monitoring_session(self, scan_results):
        """Update current monitoring session with scan results"""
        conn = sqlite3.connect(self.monitor_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE monitoring_sessions 
            SET scans_performed = scans_performed + 1,
                threats_detected = threats_detected + ?,
                alerts_generated = alerts_generated + ?
            WHERE status = 'active'
            ORDER BY id DESC LIMIT 1
        ''', (scan_results['suspicious_apps'], scan_results['suspicious_apps']))
        
        conn.commit()
        conn.close()
    
    def setup_dashboard_routes(self):
        """Setup Flask routes for monitoring dashboard"""
        
        @self.app.route('/api/monitor/status')
        def get_monitor_status():
            """Get current monitoring status"""
            return jsonify({
                'monitoring_active': self.monitoring_active,
                'scan_interval': self.scan_interval_minutes,
                'alert_threshold': self.alert_threshold,
                'timestamp': datetime.now().isoformat()
            })
        
        @self.app.route('/api/monitor/alerts')
        def get_recent_alerts():
            """Get recent alerts"""
            conn = sqlite3.connect(self.monitor_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT alert_timestamp, alert_type, severity, apk_name, risk_score, description, status
                FROM realtime_alerts 
                ORDER BY alert_timestamp DESC 
                LIMIT 50
            ''')
            
            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    'timestamp': row[0],
                    'type': row[1],
                    'severity': row[2],
                    'apk_name': row[3],
                    'risk_score': row[4],
                    'description': row[5],
                    'status': row[6]
                })
            
            conn.close()
            return jsonify({'alerts': alerts})
        
        @self.app.route('/api/monitor/health')
        def get_system_health():
            """Get system health status"""
            conn = sqlite3.connect(self.monitor_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM system_health 
                ORDER BY check_timestamp DESC 
                LIMIT 1
            ''')
            
            health_row = cursor.fetchone()
            conn.close()
            
            if health_row:
                health_data = {
                    'timestamp': health_row[1],
                    'cpu_usage': health_row[2],
                    'memory_usage': health_row[3],
                    'disk_usage': health_row[4],
                    'scanner_status': health_row[5],
                    'api_status': health_row[6],
                    'database_status': health_row[7]
                }
            else:
                health_data = {'status': 'no_data'}
            
            return jsonify(health_data)
        
        @self.app.route('/api/monitor/statistics')
        def get_monitoring_statistics():
            """Get monitoring statistics"""
            # Get scanner statistics
            scanner_stats = self.scanner.get_scan_statistics()
            
            # Get monitoring session stats
            conn = sqlite3.connect(self.monitor_db)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT scans_performed, threats_detected, alerts_generated
                FROM monitoring_sessions 
                WHERE status = 'active'
                ORDER BY id DESC LIMIT 1
            ''')
            
            session_stats = cursor.fetchone()
            
            # Get alert counts by severity
            cursor.execute('''
                SELECT severity, COUNT(*) 
                FROM realtime_alerts 
                WHERE alert_timestamp > datetime('now', '-24 hours')
                GROUP BY severity
            ''')
            
            alert_counts = dict(cursor.fetchall())
            conn.close()
            
            return jsonify({
                'scanner_stats': scanner_stats,
                'session_stats': {
                    'scans_performed': session_stats[0] if session_stats else 0,
                    'threats_detected': session_stats[1] if session_stats else 0,
                    'alerts_generated': session_stats[2] if session_stats else 0
                },
                'alert_counts': alert_counts
            })
        
        @self.app.route('/dashboard')
        def monitoring_dashboard():
            """Monitoring dashboard HTML"""
            dashboard_html = '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Hackathon APK Monitor Dashboard</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: white; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; margin-bottom: 20px; }
                    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 20px; }
                    .stat-card { background: #2a2a2a; padding: 20px; border-radius: 10px; border-left: 4px solid #667eea; }
                    .alert-high { border-left-color: #ff4757; }
                    .alert-medium { border-left-color: #ffa502; }
                    .alert-low { border-left-color: #2ed573; }
                    .alerts-section { background: #2a2a2a; padding: 20px; border-radius: 10px; }
                    .alert-item { padding: 10px; margin: 5px 0; border-radius: 5px; background: #3a3a3a; }
                    h1, h2, h3 { margin-top: 0; }
                    .status-active { color: #2ed573; }
                    .status-error { color: #ff4757; }
                </style>
                <script>
                    function updateDashboard() {
                        fetch('/api/monitor/statistics')
                            .then(response => response.json())
                            .then(data => {
                                document.getElementById('scans-performed').textContent = data.session_stats.scans_performed;
                                document.getElementById('threats-detected').textContent = data.session_stats.threats_detected;
                                document.getElementById('alerts-generated').textContent = data.session_stats.alerts_generated;
                            });
                        
                        fetch('/api/monitor/alerts')
                            .then(response => response.json())
                            .then(data => {
                                const alertsContainer = document.getElementById('alerts-container');
                                alertsContainer.innerHTML = '';
                                data.alerts.slice(0, 10).forEach(alert => {
                                    const alertDiv = document.createElement('div');
                                    alertDiv.className = `alert-item alert-${alert.severity.toLowerCase()}`;
                                    alertDiv.innerHTML = `
                                        <strong>${alert.severity}</strong> - ${alert.type}<br>
                                        <small>${alert.timestamp}</small><br>
                                        ${alert.description}
                                    `;
                                    alertsContainer.appendChild(alertDiv);
                                });
                            });
                    }
                    
                    setInterval(updateDashboard, 30000); // Update every 30 seconds
                    window.onload = updateDashboard;
                </script>
            </head>
            <body>
                <div class="header">
                    <h1>🛡️ Hackathon APK Monitoring Dashboard</h1>
                    <p>Real-time monitoring of APK repositories for fake banking app detection</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Scans Performed</h3>
                        <h2 id="scans-performed">0</h2>
                        <p>Repository scans in current session</p>
                    </div>
                    
                    <div class="stat-card">
                        <h3>Threats Detected</h3>
                        <h2 id="threats-detected">0</h2>
                        <p>Suspicious APKs identified</p>
                    </div>
                    
                    <div class="stat-card">
                        <h3>Alerts Generated</h3>
                        <h2 id="alerts-generated">0</h2>
                        <p>Security alerts triggered</p>
                    </div>
                    
                    <div class="stat-card">
                        <h3>System Status</h3>
                        <h2 class="status-active">ACTIVE</h2>
                        <p>Real-time monitoring operational</p>
                    </div>
                </div>
                
                <div class="alerts-section">
                    <h2>Recent Alerts</h2>
                    <div id="alerts-container">
                        Loading alerts...
                    </div>
                </div>
            </body>
            </html>
            '''
            return dashboard_html
    
    def run_dashboard(self, host='0.0.0.0', port=5001):
        """Run monitoring dashboard"""
        print(f"[OK] Starting monitoring dashboard on http://{host}:{port}")
        self.app.run(host=host, port=port, debug=False)

def main():
    """Main function for real-time monitoring"""
    print("HACKATHON SOLUTION: REAL-TIME APK MONITORING")
    print("=" * 60)
    
    # Initialize monitor
    monitor = HackathonRealTimeMonitor()
    
    # Start monitoring
    session_id = monitor.start_monitoring()
    
    try:
        # Run dashboard in separate thread
        dashboard_thread = threading.Thread(
            target=monitor.run_dashboard, 
            kwargs={'host': '0.0.0.0', 'port': 5001},
            daemon=True
        )
        dashboard_thread.start()
        
        print(f"\n🎯 HACKATHON REAL-TIME MONITORING ACTIVE")
        print(f"📊 Dashboard: http://localhost:5001/dashboard")
        print(f"🔍 Monitoring Session: {session_id}")
        print(f"⏱️  Scan Interval: {monitor.scan_interval_minutes} minutes")
        print(f"🚨 Alert Threshold: {monitor.alert_threshold} risk score")
        print("\nPress Ctrl+C to stop monitoring...")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[STOP] Stopping real-time monitoring...")
        monitor.monitoring_active = False

if __name__ == "__main__":
    main()
