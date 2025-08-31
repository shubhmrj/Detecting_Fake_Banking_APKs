"""
Sentinel Banking APK Detection System
Advanced real-time monitoring and anomaly detection for banking APKs
Uses legitimate banking APK baseline for anomaly detection
"""

import os
import time
import json
import sqlite3
import hashlib
import threading
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from analysis.apk_analyzer import APKAnalyzer

class SentinelBankingDetector:
    """Advanced Sentinel-based banking APK detection system"""

    def __init__(self, config_path: str = "sentinel_banking_config.json"):
        self.config = self.load_config(config_path)
        self.analyzer = APKAnalyzer()
        self.is_monitoring = False
        self.database_path = "data/sentinel_banking.db"
        
        # Model components
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.feature_columns = []
        self.legitimate_baseline = {}
        self.model_trained = False
        
        # Initialize system
        self.init_database()
        self.load_or_train_model()
        
        # Statistics
        self.stats = {
            'total_scans': 0,
            'threats_detected': 0,
            'legitimate_detected': 0,
            'false_positives': 0,
            'system_start_time': datetime.now(),
            'last_scan_time': None
        }

    def load_config(self, config_path: str) -> Dict:
        """Load Sentinel configuration"""
        default_config = {
            'detection': {
                'anomaly_threshold': -0.15,  # More sensitive for banking
                'confidence_threshold': 0.8,
                'contamination_rate': 0.05,  # Expect 5% outliers
                'enable_real_time': True
            },
            'monitoring': {
                'watch_directories': [
                    "uploads/",
                    "suspicious_apks/",
                    "test_samples/"
                ],
                'scan_interval': 180,  # 3 minutes
                'auto_quarantine': True,
                'deep_analysis': True
            },
            'alerts': {
                'enable_notifications': True,
                'threat_webhook': None,
                'email_alerts': False,
                'log_level': 'INFO'
            },
            'quarantine': {
                'quarantine_dir': "quarantine/banking/",
                'retention_days': 60
            },
            'training': {
                'retrain_interval_hours': 24,
                'min_samples_for_retrain': 10,
                'auto_update_baseline': True
            }
        }

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    self._merge_config(default_config, user_config)
            except Exception as e:
                print(f"⚠️ Config loading error: {e}. Using defaults.")

        return default_config

    def _merge_config(self, default: Dict, user: Dict):
        """Recursively merge user config with defaults"""
        for key, value in user.items():
            if isinstance(value, dict) and key in default:
                self._merge_config(default[key], value)
            else:
                default[key] = value

    def init_database(self):
        """Initialize Sentinel database"""
        os.makedirs(os.path.dirname(self.database_path), exist_ok=True)
        
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()

        # Main detections table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS banking_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT NOT NULL,
                file_hash TEXT UNIQUE NOT NULL,
                app_package TEXT,
                detection_type TEXT NOT NULL,
                is_legitimate BOOLEAN NOT NULL,
                anomaly_score REAL,
                confidence_score REAL,
                risk_level TEXT,
                detection_timestamp TEXT NOT NULL,
                analysis_data TEXT,
                quarantined BOOLEAN DEFAULT 0,
                verified BOOLEAN DEFAULT 0
            )
        ''')

        # Baseline tracking table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS legitimate_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feature_name TEXT NOT NULL,
                mean_value REAL,
                std_value REAL,
                min_value REAL,
                max_value REAL,
                last_updated TEXT NOT NULL
            )
        ''')

        # System monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_monitoring (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_timestamp TEXT NOT NULL,
                files_processed INTEGER,
                threats_found INTEGER,
                scan_duration REAL,
                system_status TEXT
            )
        ''')

        conn.commit()
        conn.close()
        print("[OK] Sentinel database initialized")

    def load_or_train_model(self):
        """Load existing model or train new one"""
        model_path = "models/banking_anomaly_model.pkl"
        scaler_path = "models/banking_scaler.pkl"
        metadata_path = "models/banking_model_metadata.json"

        if all(os.path.exists(p) for p in [model_path, scaler_path, metadata_path]):
            try:
                self.isolation_forest = joblib.load(model_path)
                self.scaler = joblib.load(scaler_path)
                
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                self.feature_columns = metadata['feature_columns']
                self.legitimate_baseline = metadata.get('legitimate_baseline', {})
                self.model_trained = True
                
                print("✅ Existing banking model loaded successfully")
                return True
                
            except Exception as e:
                print(f"❌ Error loading model: {e}")
        
        print("🔄 Training new banking anomaly detection model...")
        return self.train_banking_model()

    def train_banking_model(self):
        """Train anomaly detection model using legitimate banking APKs"""
        banking_dir = os.path.join(os.path.dirname(__file__), "mp_police_datasets", "legitimate", "banking")
        
        if not os.path.exists(banking_dir):
            print(f"❌ Banking APK directory not found: {banking_dir}")
            return False

        print("🔍 Analyzing legitimate banking APKs for baseline...")
        features_list = []
        
        apk_files = [f for f in os.listdir(banking_dir) if f.endswith('.apk')]
        print(f"Found {len(apk_files)} banking APKs")
        
        for i, filename in enumerate(apk_files, 1):
            apk_path = os.path.join(banking_dir, filename)
            print(f"[{i}/{len(apk_files)}] Processing {filename}...")
            
            try:
                analysis = self.analyzer.analyze_apk(apk_path)
                
                if 'error' not in analysis:
                    features = self.extract_comprehensive_features(analysis, filename)
                    features_list.append(features)
                    print(f"✅ Successfully processed {filename}")
                else:
                    print(f"❌ Analysis error for {filename}: {analysis['error']}")
                    
            except Exception as e:
                print(f"❌ Exception processing {filename}: {str(e)}")

        if len(features_list) < 3:
            print(f"❌ Insufficient data for training. Need at least 3 APKs, got {len(features_list)}")
            return False

        # Convert to training data
        import pandas as pd
        df = pd.DataFrame(features_list)
        feature_cols = [col for col in df.columns if col not in ['filename', 'package_name']]
        
        X = df[feature_cols].fillna(0)
        self.feature_columns = feature_cols
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train isolation forest
        self.isolation_forest = IsolationForest(
            contamination=self.config['detection']['contamination_rate'],
            random_state=42,
            n_estimators=150,
            max_samples='auto',
            bootstrap=True
        )
        
        self.isolation_forest.fit(X_scaled)
        
        # Calculate baseline statistics
        self.legitimate_baseline = {
            'mean': X.mean().to_dict(),
            'std': X.std().to_dict(),
            'min': X.min().to_dict(),
            'max': X.max().to_dict(),
            'sample_count': len(features_list)
        }
        
        # Save model
        self.save_model()
        
        # Test model on training data
        predictions = self.isolation_forest.predict(X_scaled)
        anomaly_scores = self.isolation_forest.decision_function(X_scaled)
        
        normal_count = np.sum(predictions == 1)
        anomaly_count = np.sum(predictions == -1)
        
        print(f"\n🎯 Training Results:")
        print(f"   Legitimate APKs processed: {len(features_list)}")
        print(f"   Features extracted: {len(feature_cols)}")
        print(f"   Normal predictions: {normal_count}")
        print(f"   Anomaly predictions: {anomaly_count}")
        print(f"   Anomaly score range: {anomaly_scores.min():.3f} to {anomaly_scores.max():.3f}")
        
        self.model_trained = True
        return True

    def extract_comprehensive_features(self, analysis: Dict, filename: str) -> Dict:
        """Extract comprehensive features for banking APK analysis"""
        features = {'filename': filename}
        
        # Package information
        metadata = analysis.get('metadata', {})
        features['package_name'] = metadata.get('package_name', '')
        features['file_size_mb'] = metadata.get('file_size', 0) / (1024 * 1024)
        features['min_sdk'] = metadata.get('min_sdk', 0)
        features['target_sdk'] = metadata.get('target_sdk', 0)
        features['version_code'] = metadata.get('version_code', 0)
        features['is_signed'] = int(metadata.get('is_signed', False))
        features['is_debuggable'] = int(metadata.get('is_debuggable', False))
        features['uses_native_code'] = int(metadata.get('uses_native_code', False))
        
        # Permission analysis (critical for banking apps)
        permissions = analysis.get('permissions', {})
        features['total_permissions'] = permissions.get('total_count', 0)
        features['suspicious_permissions'] = len(permissions.get('suspicious_permissions', []))
        
        perm_categories = permissions.get('permission_categories', {})
        features['critical_permissions'] = len(perm_categories.get('critical', []))
        features['high_permissions'] = len(perm_categories.get('high', []))
        features['medium_permissions'] = len(perm_categories.get('medium', []))
        features['low_permissions'] = len(perm_categories.get('low', []))
        
        # Component analysis
        components = analysis.get('components', {})
        features['activity_count'] = len(components.get('activities', []))
        features['service_count'] = len(components.get('services', []))
        features['receiver_count'] = len(components.get('receivers', []))
        features['provider_count'] = len(components.get('providers', []))
        
        # Certificate analysis (crucial for banking)
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
        
        # Calculate advanced ratios
        if features['total_permissions'] > 0:
            features['dangerous_permission_ratio'] = features['suspicious_permissions'] / features['total_permissions']
            features['critical_permission_ratio'] = features['critical_permissions'] / features['total_permissions']
        else:
            features['dangerous_permission_ratio'] = 0
            features['critical_permission_ratio'] = 0
            
        if features['total_methods'] > 0:
            features['suspicious_api_ratio'] = features['suspicious_apis'] / features['total_methods']
            features['crypto_api_ratio'] = features['crypto_apis'] / features['total_methods']
        else:
            features['suspicious_api_ratio'] = 0
            features['crypto_api_ratio'] = 0
        
        # Banking-specific features
        features['has_financial_permissions'] = int(any([
            'android.permission.USE_FINGERPRINT' in str(permissions),
            'android.permission.CAMERA' in str(permissions),
            'android.permission.READ_SMS' in str(permissions)
        ]))
        
        return features

    def save_model(self):
        """Save trained model and metadata"""
        models_dir = "models"
        os.makedirs(models_dir, exist_ok=True)
        
        # Save model components
        joblib.dump(self.isolation_forest, f"{models_dir}/banking_anomaly_model.pkl")
        joblib.dump(self.scaler, f"{models_dir}/banking_scaler.pkl")
        
        # Save metadata
        metadata = {
            'model_type': 'banking_anomaly_detection',
            'algorithm': 'isolation_forest',
            'feature_columns': self.feature_columns,
            'legitimate_baseline': self.legitimate_baseline,
            'training_timestamp': datetime.now().isoformat(),
            'contamination': self.config['detection']['contamination_rate'],
            'n_estimators': 150
        }
        
        with open(f"{models_dir}/banking_model_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
            
        print(f"💾 Model saved to {models_dir}/")

    def detect_banking_threat(self, apk_path: str) -> Dict[str, Any]:
        """Comprehensive banking APK threat detection"""
        if not self.model_trained:
            return {'error': 'Model not trained', 'is_legitimate': False}
        
        try:
            # Calculate file hash
            file_hash = self.calculate_file_hash(apk_path)
            
            # Check if already analyzed
            if self.is_already_analyzed(file_hash):
                return self.get_cached_result(file_hash)
            
            # Analyze APK
            analysis = self.analyzer.analyze_apk(apk_path)
            
            if 'error' in analysis:
                return {'error': analysis['error'], 'is_legitimate': False}
            
            # Extract features
            features = self.extract_comprehensive_features(analysis, os.path.basename(apk_path))
            
            # Prepare for prediction
            feature_values = [features.get(col, 0) for col in self.feature_columns]
            X_test = np.array(feature_values).reshape(1, -1)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Predict
            prediction = self.isolation_forest.predict(X_test_scaled)[0]
            anomaly_score = self.isolation_forest.decision_function(X_test_scaled)[0]
            
            # Interpret results
            is_legitimate = prediction == 1 and anomaly_score >= self.config['detection']['anomaly_threshold']
            confidence = min(abs(anomaly_score) * 2, 1.0)  # Normalize confidence
            
            # Determine risk level
            if anomaly_score >= -0.05:
                risk_level = 'LOW'
            elif anomaly_score >= -0.15:
                risk_level = 'MEDIUM'
            elif anomaly_score >= -0.3:
                risk_level = 'HIGH'
            else:
                risk_level = 'CRITICAL'
            
            result = {
                'file_path': apk_path,
                'file_hash': file_hash,
                'package_name': features.get('package_name', 'unknown'),
                'is_legitimate': is_legitimate,
                'anomaly_score': float(anomaly_score),
                'confidence': float(confidence),
                'risk_level': risk_level,
                'detection_type': 'anomaly_detection',
                'analysis': analysis,
                'features': features,
                'timestamp': datetime.now().isoformat()
            }
            
            # Store result
            self.store_detection_result(result)
            
            # Update statistics
            self.stats['total_scans'] += 1
            if is_legitimate:
                self.stats['legitimate_detected'] += 1
            else:
                self.stats['threats_detected'] += 1
            self.stats['last_scan_time'] = datetime.now()
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'is_legitimate': False}

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

    def is_already_analyzed(self, file_hash: str) -> bool:
        """Check if file was already analyzed"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT COUNT(*) FROM banking_detections WHERE file_hash = ?",
            (file_hash,)
        )
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0

    def get_cached_result(self, file_hash: str) -> Dict:
        """Get cached analysis result"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT file_path, app_package, is_legitimate, anomaly_score, 
                   confidence_score, risk_level, detection_timestamp
            FROM banking_detections WHERE file_hash = ?
        """, (file_hash,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'file_path': row[0],
                'package_name': row[1],
                'is_legitimate': bool(row[2]),
                'anomaly_score': row[3],
                'confidence': row[4],
                'risk_level': row[5],
                'timestamp': row[6],
                'cached': True
            }
        
        return {'error': 'Cached result not found'}

    def store_detection_result(self, result: Dict):
        """Store detection result in database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO banking_detections 
            (file_path, file_hash, app_package, detection_type, is_legitimate, 
             anomaly_score, confidence_score, risk_level, detection_timestamp, analysis_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result['file_path'],
            result['file_hash'],
            result['package_name'],
            result['detection_type'],
            result['is_legitimate'],
            result['anomaly_score'],
            result['confidence'],
            result['risk_level'],
            result['timestamp'],
            json.dumps(result.get('analysis', {}))
        ))
        
        conn.commit()
        conn.close()

    def start_sentinel_monitoring(self):
        """Start continuous Sentinel monitoring"""
        print("🛡️ Starting Sentinel Banking APK Monitoring...")
        print(f"📁 Monitoring directories: {self.config['monitoring']['watch_directories']}")
        print(f"⏱️ Scan interval: {self.config['monitoring']['scan_interval']} seconds")
        print(f"🎯 Anomaly threshold: {self.config['detection']['anomaly_threshold']}")
        
        self.is_monitoring = True
        
        while self.is_monitoring:
            try:
                scan_start = time.time()
                files_processed = 0
                threats_found = 0
                
                for watch_dir in self.config['monitoring']['watch_directories']:
                    if os.path.exists(watch_dir):
                        for root, dirs, files in os.walk(watch_dir):
                            for file in files:
                                if file.endswith('.apk'):
                                    apk_path = os.path.join(root, file)
                                    result = self.detect_banking_threat(apk_path)
                                    
                                    files_processed += 1
                                    
                                    if not result.get('is_legitimate', False):
                                        threats_found += 1
                                        self.handle_threat_detection(result)
                
                scan_duration = time.time() - scan_start
                
                # Log monitoring cycle
                self.log_monitoring_cycle(files_processed, threats_found, scan_duration)
                
                print(f"🔍 Monitoring cycle: {files_processed} files, {threats_found} threats, {scan_duration:.2f}s")
                
                time.sleep(self.config['monitoring']['scan_interval'])
                
            except KeyboardInterrupt:
                print("\n🛑 Sentinel monitoring stopped by user")
                break
            except Exception as e:
                print(f"❌ Monitoring error: {e}")
                time.sleep(30)
        
        self.is_monitoring = False

    def handle_threat_detection(self, result: Dict):
        """Handle detected banking threat"""
        print(f"\n🚨 BANKING THREAT DETECTED!")
        print(f"   File: {os.path.basename(result['file_path'])}")
        print(f"   Package: {result['package_name']}")
        print(f"   Risk Level: {result['risk_level']}")
        print(f"   Anomaly Score: {result['anomaly_score']:.3f}")
        print(f"   Confidence: {result['confidence']:.3f}")
        
        # Auto-quarantine if enabled
        if self.config['monitoring']['auto_quarantine']:
            self.quarantine_suspicious_apk(result['file_path'])

    def quarantine_suspicious_apk(self, file_path: str):
        """Quarantine suspicious banking APK"""
        try:
            quarantine_dir = self.config['quarantine']['quarantine_dir']
            os.makedirs(quarantine_dir, exist_ok=True)
            
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_path = os.path.join(quarantine_dir, f"{timestamp}_{filename}")
            
            os.rename(file_path, quarantine_path)
            print(f"🔒 APK quarantined: {quarantine_path}")
            
        except Exception as e:
            print(f"❌ Quarantine failed: {e}")

    def log_monitoring_cycle(self, files_processed: int, threats_found: int, duration: float):
        """Log monitoring cycle to database"""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO system_monitoring 
            (scan_timestamp, files_processed, threats_found, scan_duration, system_status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            files_processed,
            threats_found,
            duration,
            'active'
        ))
        
        conn.commit()
        conn.close()

    def get_system_statistics(self) -> Dict:
        """Get comprehensive system statistics"""
        uptime = datetime.now() - self.stats['system_start_time']
        
        return {
            'system_uptime_hours': uptime.total_seconds() / 3600,
            'total_scans_performed': self.stats['total_scans'],
            'threats_detected': self.stats['threats_detected'],
            'legitimate_apps_detected': self.stats['legitimate_detected'],
            'false_positives': self.stats['false_positives'],
            'last_scan_time': self.stats['last_scan_time'],
            'model_trained': self.model_trained,
            'monitoring_active': self.is_monitoring,
            'baseline_sample_count': self.legitimate_baseline.get('sample_count', 0)
        }

    def stop_monitoring(self):
        """Stop Sentinel monitoring"""
        self.is_monitoring = False
        print("🛑 Sentinel Banking Monitoring stopped")


def main():
    """Main Sentinel Banking Detector interface"""
    print("🛡️ Sentinel Banking APK Detection System")
    print("=" * 60)
    
    detector = SentinelBankingDetector()
    
    if not detector.model_trained:
        print("❌ Model training failed. Cannot start Sentinel.")
        return
    
    while True:
        print("\n📋 Sentinel Banking Detector Menu:")
        print("1. Start continuous monitoring")
        print("2. Analyze single banking APK")
        print("3. Batch analyze directory")
        print("4. View system statistics")
        print("5. Retrain model")
        print("6. Exit")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == '1':
            try:
                detector.start_sentinel_monitoring()
            except KeyboardInterrupt:
                print("\n🛑 Monitoring stopped")
        
        elif choice == '2':
            apk_path = input("Enter banking APK path: ").strip()
            if os.path.exists(apk_path):
                result = detector.detect_banking_threat(apk_path)
                print(f"\n📊 Detection Result:")
                print(json.dumps(result, indent=2, default=str))
            else:
                print("❌ File not found")
        
        elif choice == '3':
            directory = input("Enter directory path: ").strip()
            if os.path.exists(directory):
                print(f"🔍 Analyzing directory: {directory}")
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file.endswith('.apk'):
                            apk_path = os.path.join(root, file)
                            result = detector.detect_banking_threat(apk_path)
                            status = "✅ LEGITIMATE" if result.get('is_legitimate') else "🚨 SUSPICIOUS"
                            print(f"{status} - {file} (Score: {result.get('anomaly_score', 0):.3f})")
            else:
                print("❌ Directory not found")
        
        elif choice == '4':
            stats = detector.get_system_statistics()
            print(f"\n📈 System Statistics:")
            print(json.dumps(stats, indent=2, default=str))
        
        elif choice == '5':
            print("🔄 Retraining model...")
            if detector.train_banking_model():
                print("✅ Model retrained successfully")
            else:
                print("❌ Model retraining failed")
        
        elif choice == '6':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option")


if __name__ == "__main__":
    main()
