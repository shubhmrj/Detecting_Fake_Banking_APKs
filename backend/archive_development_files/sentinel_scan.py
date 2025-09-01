"""
SentinelScan - Real-time APK Monitoring and Threat Detection System
Provides continuous monitoring, automated scanning, and threat intelligence
"""

import os
import time
import json
import sqlite3
import hashlib
import requests
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import joblib
import numpy as np
from analysis.enhanced_analyzer import EnhancedAPKAnalyzer

class SentinelScan:
    """Real-time APK monitoring and threat detection system"""

    def __init__(self, config_path: str = "sentinel_config.json"):
        self.config = self.load_config(config_path)
        self.analyzer = EnhancedAPKAnalyzer()
        self.is_monitoring = False
        self.threat_database = "data/sentinel_threats.db"
        self.model_loaded = False

        # Initialize components
        self.init_threat_database()
        self.load_anomaly_model()

        # Monitoring statistics
        self.stats = {
            'scans_performed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'last_scan_time': None,
            'uptime_start': datetime.now()
        }

    def load_config(self, config_path: str) -> Dict:
        """Load SentinelScan configuration"""
        default_config = {
            'monitoring': {
                'scan_interval': 300,  # 5 minutes
                'watch_directories': [
                    "uploads/",
                    "mp_police_datasets/test_samples/",
                    "suspicious_apks/"
                ],
                'auto_quarantine': True,
                'real_time_alerts': True
            },
            'detection': {
                'anomaly_threshold': -0.1,
                'confidence_threshold': 0.7,
                'enable_dynamic_analysis': False,
                'enable_network_analysis': True
            },
            'alerts': {
                'email_notifications': False,
                'webhook_url': None,
                'log_level': 'INFO'
            },
            'quarantine': {
                'quarantine_dir': "quarantine/",
                'auto_delete_after_days': 30
            }
        }

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in default_config:
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
            except Exception as e:
                print(f"⚠️ Error loading config: {e}. Using defaults.")

        return default_config

    def init_threat_database(self):
        """Initialize threat detection database"""
        os.makedirs(os.path.dirname(self.threat_database), exist_ok=True)

        conn = sqlite3.connect(self.threat_database)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                risk_score REAL NOT NULL,
                anomaly_score REAL,
                confidence REAL,
                detection_time TEXT NOT NULL,
                status TEXT DEFAULT 'detected',
                analysis_data TEXT,
                quarantined BOOLEAN DEFAULT 0
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                files_scanned INTEGER,
                threats_found INTEGER,
                scan_duration REAL,
                scan_type TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def load_anomaly_model(self):
        """Load trained anomaly detection model"""
        try:
            model_path = "models/banking_anomaly_model.pkl"
            scaler_path = "models/banking_scaler.pkl"
            metadata_path = "models/banking_model_metadata.json"

            if all(os.path.exists(p) for p in [model_path, scaler_path, metadata_path]):
                self.isolation_forest = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)

                with open(metadata_path, 'r') as f:
                    self.model_metadata = json.load(f)

                self.feature_columns = self.model_metadata['feature_columns']
                self.model_loaded = True
                print("✅ Anomaly detection model loaded successfully")
            else:
                print("⚠️ Anomaly model not found. Run train_banking_model.py first")

        except Exception as e:
            print(f"❌ Error loading model: {e}")
            self.model_loaded = False

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    def scan_apk_file(self, apk_path: str) -> Dict[str, Any]:
        """Perform comprehensive APK scan"""
        scan_start = time.time()

        try:
            # Calculate file hash
            file_hash = self.calculate_file_hash(apk_path)

            # Check if already scanned
            if self.is_already_scanned(file_hash):
                return {'status': 'already_scanned', 'hash': file_hash}

            # Analyze APK
            analysis = self.analyzer.analyze_apk(apk_path)

            if 'error' in analysis:
                return {'status': 'error', 'error': analysis['error']}

            # Extract features for anomaly detection
            threat_result = self.detect_threats(analysis, apk_path)

            # Update statistics
            self.stats['scans_performed'] += 1
            self.stats['last_scan_time'] = datetime.now()

            scan_duration = time.time() - scan_start

            result = {
                'status': 'completed',
                'file_path': apk_path,
                'file_hash': file_hash,
                'scan_duration': scan_duration,
                'analysis': analysis,
                'threat_detection': threat_result,
                'timestamp': datetime.now().isoformat()
            }

            # Log scan to database
            self.log_scan_result(result)

            return result

        except Exception as e:
            return {'status': 'error', 'error': str(e)}

    def detect_threats(self, analysis: Dict, apk_path: str) -> Dict[str, Any]:
        """Detect threats using multiple detection methods"""
        threats = {
            'is_threat': False,
            'threat_type': 'unknown',
            'risk_score': 0.0,
            'confidence': 0.0,
            'anomaly_score': None,
            'detection_methods': []
        }

        # Method 1: Anomaly Detection (if model loaded)
        if self.model_loaded:
            anomaly_result = self.anomaly_detection(analysis)
            threats.update(anomaly_result)

        # Method 2: Rule-based Detection
        rule_result = self.rule_based_detection(analysis)
        if rule_result['is_threat']:
            threats['is_threat'] = True
            threats['detection_methods'].append('rule_based')
            threats['risk_score'] = max(threats['risk_score'], rule_result['risk_score'])

        # Method 3: Signature-based Detection
        signature_result = self.signature_based_detection(analysis)
        if signature_result['is_threat']:
            threats['is_threat'] = True
            threats['detection_methods'].append('signature_based')
            threats['threat_type'] = signature_result['threat_type']

        # Method 4: Behavioral Analysis
        behavior_result = self.behavioral_analysis(analysis)
        if behavior_result['is_threat']:
            threats['is_threat'] = True
            threats['detection_methods'].append('behavioral')

        # Update threat statistics
        if threats['is_threat']:
            self.stats['threats_detected'] += 1

        return threats

    def anomaly_detection(self, analysis: Dict) -> Dict[str, Any]:
        """Perform anomaly detection using trained model"""
        try:
            # Extract features (same as training)
            features = self.extract_features_for_prediction(analysis)

            # Prepare feature vector
            feature_values = [features.get(col, 0) for col in self.feature_columns]
            X_test = np.array(feature_values).reshape(1, -1)
            X_test_scaled = self.scaler.transform(X_test)

            # Predict
            prediction = self.isolation_forest.predict(X_test_scaled)[0]
            anomaly_score = self.isolation_forest.decision_function(X_test_scaled)[0]

            is_anomaly = prediction == -1
            confidence = abs(anomaly_score)

            return {
                'is_threat': is_anomaly and anomaly_score < self.config['detection']['anomaly_threshold'],
                'threat_type': 'anomaly' if is_anomaly else 'normal',
                'anomaly_score': float(anomaly_score),
                'confidence': float(confidence),
                'risk_score': max(0, -anomaly_score * 100),
                'detection_methods': ['anomaly_detection'] if is_anomaly else []
            }

        except Exception as e:
            print(f"❌ Anomaly detection error: {e}")
            return {'is_threat': False, 'error': str(e)}

    def rule_based_detection(self, analysis: Dict) -> Dict[str, Any]:
        """Rule-based threat detection"""
        risk_score = 0
        threats_found = []

        # Check permissions
        permissions = analysis.get('permissions', {})
        suspicious_perms = permissions.get('suspicious_permissions', [])

        if len(suspicious_perms) > 10:
            risk_score += 30
            threats_found.append('excessive_permissions')

        # Check certificates
        certificates = analysis.get('certificates', {})
        if not certificates.get('has_valid_certificates', False):
            risk_score += 25
            threats_found.append('invalid_certificates')

        if certificates.get('has_self_signed', False):
            risk_score += 15
            threats_found.append('self_signed_certificate')

        # Check for suspicious APIs
        api_calls = analysis.get('api_calls', {})
        suspicious_apis = api_calls.get('suspicious_apis', [])

        if len(suspicious_apis) > 5:
            risk_score += 20
            threats_found.append('suspicious_api_usage')

        # Check URLs
        urls = analysis.get('urls', {})
        suspicious_urls = urls.get('suspicious_urls', [])

        if len(suspicious_urls) > 0:
            risk_score += 25
            threats_found.append('suspicious_urls')

        return {
            'is_threat': risk_score > 50,
            'risk_score': risk_score,
            'threats_found': threats_found
        }

    def signature_based_detection(self, analysis: Dict) -> Dict[str, Any]:
        """Signature-based malware detection"""
        # Check for known malicious patterns
        security = analysis.get('security_analysis', {})

        if security.get('has_malicious_keywords', False):
            return {
                'is_threat': True,
                'threat_type': 'known_malware_signature'
            }

        return {'is_threat': False}

    def behavioral_analysis(self, analysis: Dict) -> Dict[str, Any]:
        """Behavioral pattern analysis"""
        # Analyze app behavior patterns
        components = analysis.get('components', {})

        # Check for suspicious component combinations
        if (len(components.get('services', [])) > 10 and
            len(components.get('receivers', [])) > 5):
            return {
                'is_threat': True,
                'threat_type': 'suspicious_behavior'
            }

        return {'is_threat': False}

    def extract_features_for_prediction(self, analysis: Dict) -> Dict:
        """Extract features for model prediction (same as training)"""
        features = {}

        # File metadata
        metadata = analysis.get('metadata', {})
        features['file_size'] = metadata.get('file_size', 0) / (1024 * 1024)
        features['min_sdk'] = metadata.get('min_sdk', 0)
        features['target_sdk'] = metadata.get('target_sdk', 0)
        features['version_code'] = metadata.get('version_code', 0)
        features['is_signed'] = int(metadata.get('is_signed', False))
        features['is_debuggable'] = int(metadata.get('is_debuggable', False))
        features['uses_native_code'] = int(metadata.get('uses_native_code', False))

        # Permission analysis
        permissions = analysis.get('permissions', {})
        features['total_permissions'] = permissions.get('total_count', 0)
        features['suspicious_permissions'] = len(permissions.get('suspicious_permissions', []))
        features['critical_permissions'] = len(permissions.get('permission_categories', {}).get('critical', []))
        features['high_permissions'] = len(permissions.get('permission_categories', {}).get('high', []))
        features['medium_permissions'] = len(permissions.get('permission_categories', {}).get('medium', []))
        features['low_permissions'] = len(permissions.get('permission_categories', {}).get('low', []))

        # Component analysis
        components = analysis.get('components', {})
        features['activity_count'] = len(components.get('activities', []))
        features['service_count'] = len(components.get('services', []))
        features['receiver_count'] = len(components.get('receivers', []))
        features['provider_count'] = len(components.get('providers', []))

        # Certificate analysis
        certificates = analysis.get('certificates', {})
        features['certificate_count'] = certificates.get('certificate_count', 0)
        features['has_valid_certificates'] = int(certificates.get('has_valid_certificates', False))
        features['has_self_signed'] = int(certificates.get('has_self_signed', False))

        # API usage analysis
        api_calls = analysis.get('api_calls', {})
        features['total_methods'] = api_calls.get('total_methods', 0)
        features['suspicious_apis'] = len(api_calls.get('suspicious_apis', []))
        features['crypto_apis'] = len(api_calls.get('crypto_apis', []))
        features['network_apis'] = len(api_calls.get('network_apis', []))
        features['telephony_apis'] = len(api_calls.get('telephony_apis', []))

        # URL and network analysis
        urls = analysis.get('urls', {})
        features['http_urls'] = len(urls.get('http_urls', []))
        features['https_urls'] = len(urls.get('https_urls', []))
        features['suspicious_urls'] = len(urls.get('suspicious_urls', []))
        features['ip_addresses'] = len(urls.get('ip_addresses', []))

        # Security analysis
        security = analysis.get('security_analysis', {})
        features['risk_score'] = security.get('risk_score', 0)
        features['has_banking_keywords'] = int(security.get('has_banking_keywords', False))
        features['suspicious_package_name'] = int(security.get('suspicious_package_name', False))

        # Calculate ratios
        if features['total_permissions'] > 0:
            features['dangerous_permission_ratio'] = features['suspicious_permissions'] / features['total_permissions']
        else:
            features['dangerous_permission_ratio'] = 0

        if features['total_methods'] > 0:
            features['suspicious_api_ratio'] = features['suspicious_apis'] / features['total_methods']
        else:
            features['suspicious_api_ratio'] = 0

        return features

    def is_already_scanned(self, file_hash: str) -> bool:
        """Check if file was already scanned"""
        conn = sqlite3.connect(self.threat_database)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM threat_detections WHERE file_hash = ?",
            (file_hash,)
        )

        count = cursor.fetchone()[0]
        conn.close()

        return count > 0

    def log_scan_result(self, result: Dict):
        """Log scan result to database"""
        if result['status'] != 'completed':
            return

        threat = result['threat_detection']

        conn = sqlite3.connect(self.threat_database)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO threat_detections 
            (file_path, file_hash, threat_type, risk_score, anomaly_score, 
             confidence, detection_time, analysis_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result['file_path'],
            result['file_hash'],
            threat['threat_type'],
            threat['risk_score'],
            threat.get('anomaly_score'),
            threat['confidence'],
            result['timestamp'],
            json.dumps(result['analysis'])
        ))

        conn.commit()
        conn.close()

    def start_monitoring(self):
        """Start continuous monitoring"""
        print("🛡️ Starting SentinelScan monitoring...")
        print(f"📁 Watching directories: {self.config['monitoring']['watch_directories']}")
        print(f"⏱️ Scan interval: {self.config['monitoring']['scan_interval']} seconds")

        self.is_monitoring = True

        while self.is_monitoring:
            try:
                scan_start = time.time()
                total_scanned = 0
                threats_found = 0

                # Scan all watch directories
                for watch_dir in self.config['monitoring']['watch_directories']:
                    if os.path.exists(watch_dir):
                        for root, dirs, files in os.walk(watch_dir):
                            for file in files:
                                if file.endswith('.apk'):
                                    apk_path = os.path.join(root, file)
                                    result = self.scan_apk_file(apk_path)

                                    total_scanned += 1

                                    if (result.get('status') == 'completed' and
                                        result.get('threat_detection', {}).get('is_threat', False)):
                                        threats_found += 1
                                        self.handle_threat_detection(result)

                scan_duration = time.time() - scan_start

                # Log scan cycle
                self.log_scan_cycle(total_scanned, threats_found, scan_duration)

                print(f"🔍 Scan cycle completed: {total_scanned} files, {threats_found} threats")

                # Wait for next scan
                time.sleep(self.config['monitoring']['scan_interval'])

            except KeyboardInterrupt:
                print("\n🛑 Monitoring stopped by user")
                break
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(10)  # Wait before retrying

        self.is_monitoring = False

    def handle_threat_detection(self, result: Dict):
        """Handle detected threat"""
        threat = result['threat_detection']
        file_path = result['file_path']

        print(f"🚨 THREAT DETECTED: {os.path.basename(file_path)}")
        print(f"   Type: {threat['threat_type']}")
        print(f"   Risk Score: {threat['risk_score']:.1f}")
        print(f"   Confidence: {threat['confidence']:.3f}")

        # Auto-quarantine if enabled
        if self.config['monitoring']['auto_quarantine']:
            self.quarantine_file(file_path)

        # Send alerts if enabled
        if self.config['alerts']['real_time_alerts']:
            self.send_alert(result)

    def quarantine_file(self, file_path: str):
        """Move suspicious file to quarantine"""
        try:
            quarantine_dir = self.config['quarantine']['quarantine_dir']
            os.makedirs(quarantine_dir, exist_ok=True)

            filename = os.path.basename(file_path)
            quarantine_path = os.path.join(quarantine_dir, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}")

            os.rename(file_path, quarantine_path)
            print(f"🔒 File quarantined: {quarantine_path}")

        except Exception as e:
            print(f"❌ Quarantine failed: {e}")

    def send_alert(self, result: Dict):
        """Send threat alert"""
        # Implement webhook/email notifications here
        webhook_url = self.config['alerts'].get('webhook_url')

        if webhook_url:
            try:
                alert_data = {
                    'timestamp': result['timestamp'],
                    'file_path': result['file_path'],
                    'threat_type': result['threat_detection']['threat_type'],
                    'risk_score': result['threat_detection']['risk_score'],
                    'system': 'SentinelScan'
                }

                requests.post(webhook_url, json=alert_data, timeout=10)

            except Exception as e:
                print(f"❌ Alert sending failed: {e}")

    def log_scan_cycle(self, files_scanned: int, threats_found: int, duration: float):
        """Log scan cycle to database"""
        conn = sqlite3.connect(self.threat_database)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO scan_history 
            (scan_time, files_scanned, threats_found, scan_duration, scan_type)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            files_scanned,
            threats_found,
            duration,
            'continuous_monitoring'
        ))

        conn.commit()
        conn.close()

    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        uptime = datetime.now() - self.stats['uptime_start']

        return {
            'uptime_hours': uptime.total_seconds() / 3600,
            'scans_performed': self.stats['scans_performed'],
            'threats_detected': self.stats['threats_detected'],
            'false_positives': self.stats['false_positives'],
            'last_scan_time': self.stats['last_scan_time'],
            'model_loaded': self.model_loaded,
            'monitoring_active': self.is_monitoring
        }

    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        print("🛑 SentinelScan monitoring stopped")

def main():
    """Main SentinelScan interface"""
    print("🛡️ SentinelScan - APK Threat Detection System")
    print("=" * 50)

    sentinel = SentinelScan()

    while True:
        print("\n📋 SentinelScan Menu:")
        print("1. Start continuous monitoring")
        print("2. Scan single APK file")
        print("3. Scan directory")
        print("4. View statistics")
        print("5. View recent threats")
        print("6. Exit")

        choice = input("\nSelect option (1-6): ").strip()

        if choice == '1':
            try:
                sentinel.start_monitoring()
            except KeyboardInterrupt:
                print("\n🛑 Monitoring stopped")

        elif choice == '2':
            apk_path = input("Enter APK file path: ").strip()
            if os.path.exists(apk_path):
                result = sentinel.scan_apk_file(apk_path)
                print(f"\n📊 Scan Result: {json.dumps(result, indent=2)}")
            else:
                print("❌ File not found")

        elif choice == '3':
            directory = input("Enter directory path: ").strip()
            if os.path.exists(directory):
                print(f"🔍 Scanning directory: {directory}")
                # Implement directory scanning
            else:
                print("❌ Directory not found")

        elif choice == '4':
            stats = sentinel.get_statistics()
            print(f"\n📈 Statistics: {json.dumps(stats, indent=2, default=str)}")

        elif choice == '5':
            print("🚨 Recent threats feature coming soon...")

        elif choice == '6':
            print("👋 Goodbye!")
            break

        else:
            print("❌ Invalid option")

if __name__ == "__main__":
    main()
