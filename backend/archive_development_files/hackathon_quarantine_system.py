"""
Hackathon Solution: Automated Flagging and Quarantine System
Provides automated threat response, quarantine management, and security actions
"""

import os
import sys
import json
import shutil
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from backend.archive_development_files.hackathon_advanced_analyzer import HackathonAdvancedAnalyzer

class HackathonQuarantineSystem:
    """
    Automated flagging and quarantine system for threat response
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.quarantine_db = self.base_dir / "data" / "hackathon_quarantine.db"
        self.quarantine_dir = self.base_dir / "quarantine"
        self.logs_dir = self.base_dir / "logs"
        
        # Create directories
        self.quarantine_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        
        # Quarantine thresholds
        self.auto_quarantine_threshold = 70  # Risk score for automatic quarantine
        self.manual_review_threshold = 50    # Risk score for manual review
        self.immediate_block_threshold = 85  # Risk score for immediate blocking
        
        # Initialize advanced analyzer
        self.analyzer = HackathonAdvancedAnalyzer()
        
        # Setup quarantine database
        self.setup_quarantine_database()
        
        print("[OK] Quarantine System initialized")
    
    def setup_quarantine_database(self):
        """Setup quarantine management database"""
        conn = sqlite3.connect(self.quarantine_db)
        cursor = conn.cursor()
        
        # Quarantined items table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantined_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_path TEXT NOT NULL,
                apk_hash TEXT NOT NULL,
                package_name TEXT,
                quarantine_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- Threat information
                risk_score REAL NOT NULL,
                threat_category TEXT,
                threat_description TEXT,
                detection_method TEXT,
                
                -- Quarantine details
                quarantine_reason TEXT NOT NULL,
                quarantine_action TEXT NOT NULL,
                quarantine_location TEXT,
                auto_quarantined BOOLEAN DEFAULT 1,
                
                -- Status tracking
                status TEXT DEFAULT 'quarantined',
                reviewed_by TEXT,
                review_timestamp TIMESTAMP,
                resolution TEXT,
                
                -- Metadata
                original_source TEXT,
                file_size INTEGER,
                quarantine_duration INTEGER
            )
        ''')
        
        # Security actions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                action_type TEXT NOT NULL,
                target_apk TEXT,
                target_hash TEXT,
                
                -- Action details
                action_description TEXT,
                severity_level TEXT,
                automated BOOLEAN DEFAULT 1,
                
                -- Results
                action_status TEXT DEFAULT 'pending',
                execution_result TEXT,
                error_message TEXT,
                
                -- Context
                triggered_by TEXT,
                related_alert_id INTEGER
            )
        ''')
        
        # Threat intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intelligence_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- Threat data
                threat_hash TEXT NOT NULL,
                threat_signature TEXT,
                threat_family TEXT,
                threat_category TEXT,
                
                -- Intelligence source
                source_type TEXT,
                source_name TEXT,
                confidence_level REAL,
                
                -- Threat details
                description TEXT,
                indicators TEXT,
                mitigation_advice TEXT,
                
                -- Status
                active BOOLEAN DEFAULT 1,
                last_seen TIMESTAMP
            )
        ''')
        
        # Notification log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notification_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                notification_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notification_type TEXT NOT NULL,
                recipient TEXT,
                subject TEXT,
                message TEXT,
                delivery_status TEXT DEFAULT 'pending',
                delivery_timestamp TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[OK] Quarantine database initialized")
    
    def process_threat_detection(self, apk_path: str, analysis_results: Dict) -> Dict:
        """
        Process threat detection and determine appropriate response
        """
        print(f"\n[THREAT PROCESSING] {Path(apk_path).name}")
        
        risk_score = analysis_results.get('overall_risk_score', 0)
        package_name = analysis_results.get('package_name', 'Unknown')
        
        response_actions = {
            'quarantine_required': False,
            'block_required': False,
            'manual_review_required': False,
            'notifications_sent': [],
            'actions_taken': []
        }
        
        # Determine response based on risk score
        if risk_score >= self.immediate_block_threshold:
            # Immediate blocking and quarantine
            response_actions['block_required'] = True
            response_actions['quarantine_required'] = True
            
            quarantine_result = self.quarantine_apk(
                apk_path, analysis_results, 
                reason="IMMEDIATE_THREAT",
                action="BLOCK_AND_QUARANTINE"
            )
            response_actions['actions_taken'].append(quarantine_result)
            
            # Send high-priority alert
            self.send_security_alert(
                "CRITICAL_THREAT_DETECTED",
                f"Critical threat detected: {package_name} (Risk: {risk_score:.1f})",
                analysis_results
            )
            response_actions['notifications_sent'].append("CRITICAL_ALERT")
            
        elif risk_score >= self.auto_quarantine_threshold:
            # Automatic quarantine
            response_actions['quarantine_required'] = True
            
            quarantine_result = self.quarantine_apk(
                apk_path, analysis_results,
                reason="HIGH_RISK_DETECTION",
                action="AUTO_QUARANTINE"
            )
            response_actions['actions_taken'].append(quarantine_result)
            
            # Send standard alert
            self.send_security_alert(
                "HIGH_RISK_THREAT",
                f"High-risk APK quarantined: {package_name} (Risk: {risk_score:.1f})",
                analysis_results
            )
            response_actions['notifications_sent'].append("HIGH_RISK_ALERT")
            
        elif risk_score >= self.manual_review_threshold:
            # Manual review required
            response_actions['manual_review_required'] = True
            
            self.flag_for_manual_review(apk_path, analysis_results)
            response_actions['actions_taken'].append("FLAGGED_FOR_REVIEW")
            
            # Send review notification
            self.send_review_notification(
                f"APK flagged for review: {package_name} (Risk: {risk_score:.1f})",
                analysis_results
            )
            response_actions['notifications_sent'].append("REVIEW_NOTIFICATION")
        
        # Log security action
        self.log_security_action(
            "THREAT_RESPONSE",
            apk_path,
            f"Processed threat with risk score {risk_score:.1f}",
            "HIGH" if risk_score >= self.auto_quarantine_threshold else "MEDIUM"
        )
        
        print(f"[OK] Threat processing completed - Actions: {len(response_actions['actions_taken'])}")
        
        return response_actions
    
    def quarantine_apk(self, apk_path: str, analysis_results: Dict, reason: str, action: str) -> Dict:
        """
        Quarantine an APK file
        """
        try:
            apk_file = Path(apk_path)
            apk_hash = analysis_results.get('apk_hash', 'unknown')
            
            # Create quarantine subdirectory based on date
            quarantine_subdir = self.quarantine_dir / datetime.now().strftime('%Y-%m-%d')
            quarantine_subdir.mkdir(exist_ok=True)
            
            # Generate quarantine filename
            quarantine_filename = f"{apk_hash[:16]}_{apk_file.name}"
            quarantine_path = quarantine_subdir / quarantine_filename
            
            # Copy APK to quarantine
            shutil.copy2(apk_path, quarantine_path)
            
            # Record quarantine in database
            quarantine_id = self.record_quarantine(
                apk_path, analysis_results, reason, action, str(quarantine_path)
            )
            
            # Create quarantine metadata file
            metadata = {
                'quarantine_id': quarantine_id,
                'original_path': str(apk_path),
                'quarantine_timestamp': datetime.now().isoformat(),
                'reason': reason,
                'action': action,
                'analysis_results': analysis_results
            }
            
            metadata_path = quarantine_path.with_suffix('.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            print(f"[QUARANTINE] {apk_file.name} -> {quarantine_filename}")
            
            return {
                'success': True,
                'quarantine_id': quarantine_id,
                'quarantine_path': str(quarantine_path),
                'action': action,
                'reason': reason
            }
            
        except Exception as e:
            error_msg = f"Quarantine failed: {str(e)}"
            print(f"[ERROR] {error_msg}")
            
            return {
                'success': False,
                'error': error_msg
            }
    
    def record_quarantine(self, apk_path: str, analysis_results: Dict, reason: str, action: str, quarantine_location: str) -> int:
        """Record quarantine in database"""
        conn = sqlite3.connect(self.quarantine_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO quarantined_items (
                apk_path, apk_hash, package_name, risk_score, threat_category,
                threat_description, detection_method, quarantine_reason,
                quarantine_action, quarantine_location, original_source, file_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            apk_path,
            analysis_results.get('apk_hash', ''),
            analysis_results.get('package_name', ''),
            analysis_results.get('overall_risk_score', 0),
            'BANKING_MALWARE',
            f"Suspicious banking APK with risk score {analysis_results.get('overall_risk_score', 0):.1f}",
            'ADVANCED_ANALYSIS',
            reason,
            action,
            quarantine_location,
            'REPOSITORY_SCAN',
            Path(apk_path).stat().st_size if Path(apk_path).exists() else 0
        ))
        
        quarantine_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return quarantine_id
    
    def flag_for_manual_review(self, apk_path: str, analysis_results: Dict):
        """Flag APK for manual review"""
        # Create review directory
        review_dir = self.base_dir / "manual_review"
        review_dir.mkdir(exist_ok=True)
        
        # Copy APK to review directory
        apk_file = Path(apk_path)
        review_path = review_dir / f"review_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{apk_file.name}"
        shutil.copy2(apk_path, review_path)
        
        # Create review report
        review_report = {
            'apk_path': str(apk_path),
            'review_path': str(review_path),
            'flagged_timestamp': datetime.now().isoformat(),
            'risk_score': analysis_results.get('overall_risk_score', 0),
            'analysis_summary': {
                'package_name': analysis_results.get('package_name'),
                'suspicious_api_count': analysis_results.get('suspicious_api_count', 0),
                'banking_keyword_count': analysis_results.get('banking_keyword_count', 0),
                'fake_banking_indicators': analysis_results.get('fake_banking_indicators', 0)
            },
            'review_priority': 'HIGH' if analysis_results.get('overall_risk_score', 0) >= 60 else 'MEDIUM',
            'recommended_action': 'DETAILED_ANALYSIS'
        }
        
        report_path = review_path.with_suffix('.review.json')
        with open(report_path, 'w') as f:
            json.dump(review_report, f, indent=2)
        
        print(f"[MANUAL REVIEW] {apk_file.name} flagged for review")
    
    def send_security_alert(self, alert_type: str, message: str, analysis_results: Dict):
        """Send security alert notification"""
        try:
            # In a real implementation, this would send actual emails/SMS/Slack notifications
            # For hackathon demo, we'll log the notification
            
            notification_data = {
                'timestamp': datetime.now().isoformat(),
                'alert_type': alert_type,
                'message': message,
                'apk_details': {
                    'package_name': analysis_results.get('package_name'),
                    'risk_score': analysis_results.get('overall_risk_score'),
                    'apk_hash': analysis_results.get('apk_hash', '')[:16]
                }
            }
            
            # Log notification
            self.log_notification(alert_type, "security_team@company.com", message, message)
            
            # Write to alert log file
            alert_log_path = self.logs_dir / f"security_alerts_{datetime.now().strftime('%Y-%m-%d')}.log"
            with open(alert_log_path, 'a') as f:
                f.write(f"{datetime.now().isoformat()} - {alert_type}: {message}\n")
            
            print(f"[ALERT SENT] {alert_type}: {message}")
            
        except Exception as e:
            print(f"[ERROR] Alert sending failed: {str(e)}")
    
    def send_review_notification(self, message: str, analysis_results: Dict):
        """Send manual review notification"""
        try:
            # Log review notification
            self.log_notification("MANUAL_REVIEW", "review_team@company.com", "Manual Review Required", message)
            
            # Write to review log
            review_log_path = self.logs_dir / f"review_notifications_{datetime.now().strftime('%Y-%m-%d')}.log"
            with open(review_log_path, 'a') as f:
                f.write(f"{datetime.now().isoformat()} - REVIEW: {message}\n")
            
            print(f"[REVIEW NOTIFICATION] {message}")
            
        except Exception as e:
            print(f"[ERROR] Review notification failed: {str(e)}")
    
    def log_security_action(self, action_type: str, target_apk: str, description: str, severity: str):
        """Log security action"""
        conn = sqlite3.connect(self.quarantine_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_actions (
                action_type, target_apk, action_description, severity_level,
                action_status, triggered_by
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            action_type,
            target_apk,
            description,
            severity,
            'completed',
            'AUTOMATED_SYSTEM'
        ))
        
        conn.commit()
        conn.close()
    
    def log_notification(self, notification_type: str, recipient: str, subject: str, message: str):
        """Log notification"""
        conn = sqlite3.connect(self.quarantine_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO notification_log (
                notification_type, recipient, subject, message, delivery_status
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            notification_type,
            recipient,
            subject,
            message,
            'sent'
        ))
        
        conn.commit()
        conn.close()
    
    def get_quarantine_statistics(self) -> Dict:
        """Get quarantine statistics"""
        conn = sqlite3.connect(self.quarantine_db)
        cursor = conn.cursor()
        
        # Total quarantined items
        cursor.execute('SELECT COUNT(*) FROM quarantined_items')
        total_quarantined = cursor.fetchone()[0]
        
        # Quarantined today
        cursor.execute('''
            SELECT COUNT(*) FROM quarantined_items 
            WHERE DATE(quarantine_timestamp) = DATE('now')
        ''')
        quarantined_today = cursor.fetchone()[0]
        
        # By threat category
        cursor.execute('''
            SELECT threat_category, COUNT(*) 
            FROM quarantined_items 
            GROUP BY threat_category
        ''')
        by_category = dict(cursor.fetchall())
        
        # By risk score ranges
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN risk_score >= 85 THEN 'CRITICAL'
                    WHEN risk_score >= 70 THEN 'HIGH'
                    WHEN risk_score >= 50 THEN 'MEDIUM'
                    ELSE 'LOW'
                END as risk_level,
                COUNT(*)
            FROM quarantined_items
            GROUP BY risk_level
        ''')
        by_risk_level = dict(cursor.fetchall())
        
        # Recent actions
        cursor.execute('''
            SELECT action_type, COUNT(*) 
            FROM security_actions 
            WHERE DATE(action_timestamp) = DATE('now')
            GROUP BY action_type
        ''')
        recent_actions = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_quarantined': total_quarantined,
            'quarantined_today': quarantined_today,
            'by_category': by_category,
            'by_risk_level': by_risk_level,
            'recent_actions': recent_actions,
            'quarantine_directory': str(self.quarantine_dir),
            'last_updated': datetime.now().isoformat()
        }
    
    def cleanup_old_quarantine(self, days_old: int = 30):
        """Cleanup old quarantine files"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            conn = sqlite3.connect(self.quarantine_db)
            cursor = conn.cursor()
            
            # Get old quarantine items
            cursor.execute('''
                SELECT id, quarantine_location 
                FROM quarantined_items 
                WHERE quarantine_timestamp < ? AND status = 'quarantined'
            ''', (cutoff_date,))
            
            old_items = cursor.fetchall()
            
            cleaned_count = 0
            for item_id, quarantine_location in old_items:
                try:
                    # Remove files
                    quarantine_path = Path(quarantine_location)
                    if quarantine_path.exists():
                        quarantine_path.unlink()
                    
                    # Remove metadata file
                    metadata_path = quarantine_path.with_suffix('.json')
                    if metadata_path.exists():
                        metadata_path.unlink()
                    
                    # Update database status
                    cursor.execute('''
                        UPDATE quarantined_items 
                        SET status = 'cleaned', resolution = 'AUTO_CLEANUP'
                        WHERE id = ?
                    ''', (item_id,))
                    
                    cleaned_count += 1
                    
                except Exception as e:
                    print(f"[WARNING] Cleanup failed for item {item_id}: {str(e)}")
            
            conn.commit()
            conn.close()
            
            print(f"[CLEANUP] Removed {cleaned_count} old quarantine items")
            
            return cleaned_count
            
        except Exception as e:
            print(f"[ERROR] Quarantine cleanup failed: {str(e)}")
            return 0

def main():
    """Test quarantine system"""
    quarantine_system = HackathonQuarantineSystem()
    
    # Display statistics
    stats = quarantine_system.get_quarantine_statistics()
    
    print("\nQUARANTINE SYSTEM STATUS")
    print("=" * 40)
    print(f"Total Quarantined: {stats['total_quarantined']}")
    print(f"Quarantined Today: {stats['quarantined_today']}")
    print(f"Quarantine Directory: {stats['quarantine_directory']}")
    
    if stats['by_risk_level']:
        print("\nBy Risk Level:")
        for level, count in stats['by_risk_level'].items():
            print(f"  {level}: {count}")
    
    if stats['recent_actions']:
        print("\nRecent Actions:")
        for action, count in stats['recent_actions'].items():
            print(f"  {action}: {count}")

if __name__ == "__main__":
    main()
