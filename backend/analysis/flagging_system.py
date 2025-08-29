"""
APK Flagging and Reporting System
Automated system for flagging suspicious APKs and generating alerts
"""

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

class APKFlaggingSystem:
    """System for flagging and reporting suspicious APKs"""
    
    def __init__(self, db_path: str = "data/flagging_system.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Flagging thresholds
        self.thresholds = {
            'critical': 80,
            'high': 60,
            'medium': 40,
            'low': 20
        }
        
        # Alert configuration
        self.alert_config = {
            'email_enabled': False,
            'webhook_enabled': False,
            'log_enabled': True,
            'recipients': [],
            'webhook_url': None
        }
        
        self.logger = self._setup_logging()
    
    def _init_database(self):
        """Initialize SQLite database for flagging system"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Flagged APKs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS flagged_apks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                package_name TEXT NOT NULL,
                app_name TEXT,
                risk_score REAL NOT NULL,
                severity_level TEXT NOT NULL,
                flag_reason TEXT,
                detection_method TEXT,
                flagged_timestamp TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                reviewed_by TEXT,
                review_timestamp TEXT,
                review_notes TEXT,
                source_repository TEXT,
                download_url TEXT,
                file_hash TEXT
            )
        ''')
        
        # Alert history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                recipients TEXT,
                status TEXT DEFAULT 'sent'
            )
        ''')
        
        # Threat statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_stats (
                date TEXT PRIMARY KEY,
                total_flagged INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                confirmed_threats INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _setup_logging(self):
        """Setup logging for flagging system"""
        logger = logging.getLogger('APKFlaggingSystem')
        logger.setLevel(logging.INFO)
        
        # Create logs directory
        log_dir = self.db_path.parent / 'logs'
        log_dir.mkdir(exist_ok=True)
        
        handler = logging.FileHandler(log_dir / 'flagging_system.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def flag_apk(self, analysis_result: Dict[str, Any], detection_method: str = 'automated') -> Dict[str, Any]:
        """Flag an APK as suspicious based on analysis results"""
        
        risk_score = analysis_result.get('risk_score', 0)
        package_name = analysis_result.get('package_name', 'unknown')
        app_name = analysis_result.get('app_name', 'unknown')
        
        # Determine severity level
        severity = self._calculate_severity(risk_score)
        
        # Generate flag reason
        flag_reason = self._generate_flag_reason(analysis_result)
        
        # Store in database
        flag_id = self._store_flagged_apk({
            'package_name': package_name,
            'app_name': app_name,
            'risk_score': risk_score,
            'severity_level': severity,
            'flag_reason': flag_reason,
            'detection_method': detection_method,
            'source_repository': analysis_result.get('source_repository'),
            'download_url': analysis_result.get('download_url'),
            'file_hash': analysis_result.get('file_hash')
        })
        
        # Generate alert if severity is high enough
        if severity in ['critical', 'high']:
            self._generate_alert(flag_id, severity, package_name, app_name, risk_score, flag_reason)
        
        # Update statistics
        self._update_threat_statistics(severity)
        
        # Log the flagging
        self.logger.info(f"APK flagged: {package_name} (Risk: {risk_score}, Severity: {severity})")
        
        return {
            'flag_id': flag_id,
            'severity': severity,
            'risk_score': risk_score,
            'flag_reason': flag_reason,
            'alert_generated': severity in ['critical', 'high']
        }
    
    def _calculate_severity(self, risk_score: float) -> str:
        """Calculate severity level based on risk score"""
        if risk_score >= self.thresholds['critical']:
            return 'critical'
        elif risk_score >= self.thresholds['high']:
            return 'high'
        elif risk_score >= self.thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _generate_flag_reason(self, analysis_result: Dict[str, Any]) -> str:
        """Generate human-readable flag reason"""
        reasons = []
        
        # Check suspicious permissions
        suspicious_perms = analysis_result.get('suspicious_permissions', [])
        if suspicious_perms:
            reasons.append(f"Suspicious permissions: {', '.join(suspicious_perms[:3])}")
        
        # Check certificate issues
        if analysis_result.get('has_self_signed_cert', False):
            reasons.append("Self-signed certificate")
        
        # Check package name issues
        if analysis_result.get('package_name_suspicious', False):
            reasons.append("Suspicious package name")
        
        # Check obfuscation
        if analysis_result.get('obfuscation_detected', False):
            reasons.append("Code obfuscation detected")
        
        # Check mimicry
        mimicry = analysis_result.get('banking_app_mimicry', {})
        if mimicry.get('package_name_similarity'):
            reasons.append("Mimicking legitimate banking app")
        
        return '; '.join(reasons) if reasons else "Multiple risk factors detected"
    
    def _store_flagged_apk(self, flag_data: Dict[str, Any]) -> int:
        """Store flagged APK in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO flagged_apks 
            (package_name, app_name, risk_score, severity_level, flag_reason, 
             detection_method, flagged_timestamp, source_repository, download_url, file_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            flag_data['package_name'],
            flag_data['app_name'],
            flag_data['risk_score'],
            flag_data['severity_level'],
            flag_data['flag_reason'],
            flag_data['detection_method'],
            datetime.now().isoformat(),
            flag_data.get('source_repository'),
            flag_data.get('download_url'),
            flag_data.get('file_hash')
        ))
        
        flag_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return flag_id
    
    def _generate_alert(self, flag_id: int, severity: str, package_name: str, 
                       app_name: str, risk_score: float, flag_reason: str):
        """Generate alert for high-severity flags"""
        
        alert_message = f"""
        SECURITY ALERT: Suspicious Banking APK Detected
        
        Severity: {severity.upper()}
        Package: {package_name}
        App Name: {app_name}
        Risk Score: {risk_score}/100
        
        Reason: {flag_reason}
        
        Flag ID: {flag_id}
        Timestamp: {datetime.now().isoformat()}
        
        Immediate action required for critical threats.
        """
        
        # Store alert in history
        self._store_alert_history('apk_flagged', severity, alert_message)
        
        # Send notifications based on configuration
        if self.alert_config['email_enabled']:
            self._send_email_alert(alert_message, severity)
        
        if self.alert_config['webhook_enabled']:
            self._send_webhook_alert(alert_message, severity)
        
        if self.alert_config['log_enabled']:
            self.logger.warning(f"ALERT: {alert_message}")
    
    def _store_alert_history(self, alert_type: str, severity: str, message: str):
        """Store alert in history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alert_history (alert_type, severity, message, timestamp, recipients)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_type, severity, message, datetime.now().isoformat(), 
              json.dumps(self.alert_config.get('recipients', []))))
        
        conn.commit()
        conn.close()
    
    def _update_threat_statistics(self, severity: str):
        """Update daily threat statistics"""
        today = datetime.now().date().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get or create today's stats
        cursor.execute('SELECT * FROM threat_stats WHERE date = ?', (today,))
        stats = cursor.fetchone()
        
        if stats:
            # Update existing stats
            cursor.execute(f'''
                UPDATE threat_stats 
                SET total_flagged = total_flagged + 1,
                    {severity}_count = {severity}_count + 1
                WHERE date = ?
            ''', (today,))
        else:
            # Create new stats entry
            cursor.execute(f'''
                INSERT INTO threat_stats (date, total_flagged, {severity}_count)
                VALUES (?, 1, 1)
            ''', (today,))
        
        conn.commit()
        conn.close()
    
    def get_flagged_apks(self, status: str = 'active', limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of flagged APKs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM flagged_apks 
            WHERE status = ? 
            ORDER BY flagged_timestamp DESC 
            LIMIT ?
        ''', (status, limit))
        
        columns = [description[0] for description in cursor.description]
        flagged_apks = []
        
        for row in cursor.fetchall():
            apk_dict = dict(zip(columns, row))
            flagged_apks.append(apk_dict)
        
        conn.close()
        return flagged_apks
    
    def review_flagged_apk(self, flag_id: int, reviewer: str, status: str, notes: str = None):
        """Review a flagged APK (mark as false positive, confirmed threat, etc.)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE flagged_apks 
            SET status = ?, reviewed_by = ?, review_timestamp = ?, review_notes = ?
            WHERE id = ?
        ''', (status, reviewer, datetime.now().isoformat(), notes, flag_id))
        
        conn.commit()
        conn.close()
        
        # Update statistics if marking as false positive or confirmed threat
        if status in ['false_positive', 'confirmed_threat']:
            today = datetime.now().date().isoformat()
            column = 'false_positives' if status == 'false_positive' else 'confirmed_threats'
            
            cursor.execute(f'''
                UPDATE threat_stats 
                SET {column} = {column} + 1
                WHERE date = ?
            ''', (today,))
            
            conn.commit()
        
        self.logger.info(f"APK flag {flag_id} reviewed by {reviewer}: {status}")
    
    def get_threat_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get threat statistics for the last N days"""
        start_date = (datetime.now() - timedelta(days=days)).date().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                SUM(total_flagged) as total_flagged,
                SUM(critical_count) as critical_count,
                SUM(high_count) as high_count,
                SUM(medium_count) as medium_count,
                SUM(low_count) as low_count,
                SUM(false_positives) as false_positives,
                SUM(confirmed_threats) as confirmed_threats
            FROM threat_stats 
            WHERE date >= ?
        ''', (start_date,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            return {
                'period_days': days,
                'total_flagged': result[0] or 0,
                'by_severity': {
                    'critical': result[1] or 0,
                    'high': result[2] or 0,
                    'medium': result[3] or 0,
                    'low': result[4] or 0
                },
                'false_positives': result[5] or 0,
                'confirmed_threats': result[6] or 0,
                'accuracy': self._calculate_accuracy(result[5] or 0, result[6] or 0, result[0] or 0)
            }
        else:
            return {
                'period_days': days,
                'total_flagged': 0,
                'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'false_positives': 0,
                'confirmed_threats': 0,
                'accuracy': 0.0
            }
    
    def _calculate_accuracy(self, false_positives: int, confirmed_threats: int, total_reviewed: int) -> float:
        """Calculate system accuracy based on reviewed flags"""
        if total_reviewed == 0:
            return 0.0
        
        correct_predictions = confirmed_threats
        total_predictions = false_positives + confirmed_threats
        
        if total_predictions == 0:
            return 0.0
        
        return (correct_predictions / total_predictions) * 100
    
    def generate_threat_report(self, days: int = 7) -> Dict[str, Any]:
        """Generate comprehensive threat report"""
        stats = self.get_threat_statistics(days)
        recent_flags = self.get_flagged_apks('active', 10)
        
        report = {
            'report_period': f"Last {days} days",
            'generated_at': datetime.now().isoformat(),
            'summary': stats,
            'recent_threats': recent_flags,
            'recommendations': self._generate_threat_recommendations(stats)
        }
        
        return report
    
    def _generate_threat_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on threat statistics"""
        recommendations = []
        
        if stats['by_severity']['critical'] > 0:
            recommendations.append("Immediate investigation required for critical threats")
        
        if stats['total_flagged'] > 50:
            recommendations.append("High threat volume detected - consider increasing monitoring")
        
        accuracy = stats.get('accuracy', 0)
        if accuracy < 70:
            recommendations.append("Review detection thresholds to reduce false positives")
        elif accuracy > 95:
            recommendations.append("Consider lowering thresholds to catch more threats")
        
        recommendations.append("Regular review of flagged APKs recommended")
        recommendations.append("Keep threat intelligence databases updated")
        
        return recommendations
    
    def _send_email_alert(self, message: str, severity: str):
        """Send email alert (placeholder implementation)"""
        # In a real implementation, configure SMTP settings
        print(f"EMAIL ALERT ({severity}): {message}")
    
    def _send_webhook_alert(self, message: str, severity: str):
        """Send webhook alert (placeholder implementation)"""
        # In a real implementation, send HTTP POST to webhook URL
        print(f"WEBHOOK ALERT ({severity}): {message}")
