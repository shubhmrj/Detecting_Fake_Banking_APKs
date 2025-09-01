"""
Sentinel Banking APK Detection System - Windows Compatible Version
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
                'anomaly_threshold': -0.15,
                'confidence_threshold': 0.8,
                'contamination_rate': 0.05,
                'enable_real_time': True
            },
            'monitoring': {
                'watch_directories': [
                    "uploads/",
                    "suspicious_apks/",
                    "test_samples/"
                ],
                'scan_interval': 180,
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
            }
        }

        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    self._merge_config(default_config, user_config)
            except Exception as e:
                print(f"WARNING: Config loading error: {e}. Using defaults.")

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
                
                print("[OK] Existing banking model loaded successfully")
                return True
                
            except Exception as e:
                print(f"[ERROR] Error loading model: {e}")
        
        print("[INFO] Training new banking anomaly detection model...")
        return self.train_banking_model()

    def train_banking_model(self):
        """Train anomaly detection model using legitimate banking APKs"""
        banking_dir = os.path.join(os.path.dirname(__file__), "mp_police_datasets", "legitimate", "banking")
        
        if not os.path.exists(banking_dir):
            print(f"[ERROR] Banking APK directory not found: {banking_dir}")
            return False

        print("[INFO] Analyzing legitimate banking APKs for baseline...")
        features_list = []
        
        apk_files = [f for f in os.listdir(banking_dir) if f.endswith('.apk')]
        print(f"Found {len(apk_files)} banking APKs")
        
        for i, filename in enumerate(apk_files, 1):
            apk_path = os.path.join(banking_dir, filename)
            print(f"[{i}/{len(apk_files)}] Processing {filename}...")
            
            try:
                # Use basic analysis for now
                features = self.extract_basic_features(apk_path, filename)
                if features:
                    features_list.append(features)
                    print(f"[OK] Successfully processed {filename}")
                else:
                    print(f"[ERROR] Failed to extract features from {filename}")
                    
            except Exception as e:
                print(f"[ERROR] Exception processing {filename}: {str(e)}")

        if len(features_list) < 3:
            print(f"[ERROR] Insufficient data for training. Need at least 3 APKs, got {len(features_list)}")
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
        
        print(f"\n[RESULTS] Training Results:")
        print(f"   Legitimate APKs processed: {len(features_list)}")
        print(f"   Features extracted: {len(feature_cols)}")
        print(f"   Normal predictions: {normal_count}")
        print(f"   Anomaly predictions: {anomaly_count}")
        print(f"   Anomaly score range: {anomaly_scores.min():.3f} to {anomaly_scores.max():.3f}")
        
        self.model_trained = True
        return True

    def extract_basic_features(self, apk_path: str, filename: str) -> Dict:
        """Extract basic features from APK file"""
        try:
            features = {'filename': filename}
            
            # File size
            file_size = os.path.getsize(apk_path)
            features['file_size_mb'] = file_size / (1024 * 1024)
            
            # Try to extract more features using APKAnalyzer
            try:
                analysis_result = self.analyzer.analyze_apk(apk_path)
                if analysis_result and not hasattr(analysis_result, 'error'):
                    # Extract features from analysis result
                    features['package_name'] = getattr(analysis_result, 'package_name', 'unknown')
                    features['version_code'] = getattr(analysis_result, 'version_code', 0)
                    features['min_sdk'] = getattr(analysis_result, 'min_sdk', 0)
                    features['target_sdk'] = getattr(analysis_result, 'target_sdk', 0)
                    features['is_signed'] = int(getattr(analysis_result, 'is_signed', False))
                    features['permission_count'] = len(getattr(analysis_result, 'permissions', []))
                    features['activity_count'] = len(getattr(analysis_result, 'activities', []))
                    features['service_count'] = len(getattr(analysis_result, 'services', []))
                else:
                    # Use default values if analysis fails
                    features.update(self._get_default_features())
            except Exception as e:
                print(f"[WARNING] Analysis failed for {filename}, using basic features: {e}")
                features.update(self._get_default_features())
            
            return features
            
        except Exception as e:
            print(f"[ERROR] Failed to extract features from {filename}: {e}")
            return None

    def _get_default_features(self) -> Dict:
        """Get default feature values when analysis fails"""
        return {
            'package_name': 'unknown',
            'version_code': 1,
            'min_sdk': 21,
            'target_sdk': 28,
            'is_signed': 1,
            'permission_count': 10,
            'activity_count': 5,
            'service_count': 2
        }

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
            
        print(f"[OK] Model saved to {models_dir}/")

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
            
            # Extract features
            features = self.extract_basic_features(apk_path, os.path.basename(apk_path))
            
            if not features:
                return {'error': 'Feature extraction failed', 'is_legitimate': False}
            
            # Prepare for prediction
            feature_values = [features.get(col, 0) for col in self.feature_columns]
            X_test = np.array(feature_values).reshape(1, -1)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Predict
            prediction = self.isolation_forest.predict(X_test_scaled)[0]
            anomaly_score = self.isolation_forest.decision_function(X_test_scaled)[0]
            
            # Interpret results
            is_legitimate = prediction == 1 and anomaly_score >= self.config['detection']['anomaly_threshold']
            confidence = min(abs(anomaly_score) * 2, 1.0)
            
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
             anomaly_score, confidence_score, risk_level, detection_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result['file_path'],
            result['file_hash'],
            result['package_name'],
            result['detection_type'],
            result['is_legitimate'],
            result['anomaly_score'],
            result['confidence'],
            result['risk_level'],
            result['timestamp']
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
            'baseline_sample_count': self.legitimate_baseline.get('sample_count', 0)
        }


def main():
    """Main Sentinel Banking Detector interface"""
    print("SENTINEL BANKING APK DETECTION SYSTEM")
    print("=" * 60)
    
    detector = SentinelBankingDetector()
    
    if not detector.model_trained:
        print("[ERROR] Model training failed. Cannot start Sentinel.")
        return
    
    while True:
        print("\nSENTINEL BANKING DETECTOR MENU:")
        print("1. Analyze single banking APK")
        print("2. Batch analyze directory")
        print("3. View system statistics")
        print("4. Retrain model")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            apk_path = input("Enter banking APK path: ").strip()
            if os.path.exists(apk_path):
                print(f"[INFO] Analyzing {os.path.basename(apk_path)}...")
                result = detector.detect_banking_threat(apk_path)
                
                print(f"\n[RESULTS] Detection Result:")
                if result.get('is_legitimate'):
                    print(f"[OK] LEGITIMATE BANKING APK")
                else:
                    print(f"[THREAT] SUSPICIOUS APK DETECTED")
                
                print(f"   Package: {result.get('package_name', 'unknown')}")
                print(f"   Risk Level: {result.get('risk_level', 'unknown')}")
                print(f"   Anomaly Score: {result.get('anomaly_score', 0):.3f}")
                print(f"   Confidence: {result.get('confidence', 0):.3f}")
                
                if 'error' in result:
                    print(f"   Error: {result['error']}")
            else:
                print("[ERROR] File not found")
        
        elif choice == '2':
            directory = input("Enter directory path: ").strip()
            if os.path.exists(directory):
                print(f"[INFO] Analyzing directory: {directory}")
                apk_count = 0
                threat_count = 0
                
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file.endswith('.apk'):
                            apk_path = os.path.join(root, file)
                            result = detector.detect_banking_threat(apk_path)
                            apk_count += 1
                            
                            if result.get('is_legitimate'):
                                status = "[OK] LEGITIMATE"
                            else:
                                status = "[THREAT] SUSPICIOUS"
                                threat_count += 1
                            
                            score = result.get('anomaly_score', 0)
                            print(f"{status} - {file} (Score: {score:.3f})")
                
                print(f"\n[SUMMARY] Processed {apk_count} APKs, found {threat_count} threats")
            else:
                print("[ERROR] Directory not found")
        
        elif choice == '3':
            stats = detector.get_system_statistics()
            print(f"\n[STATISTICS] System Statistics:")
            print(f"   System Uptime: {stats['system_uptime_hours']:.2f} hours")
            print(f"   Total Scans: {stats['total_scans_performed']}")
            print(f"   Threats Detected: {stats['threats_detected']}")
            print(f"   Legitimate Apps: {stats['legitimate_apps_detected']}")
            print(f"   Model Trained: {stats['model_trained']}")
            print(f"   Baseline Samples: {stats['baseline_sample_count']}")
        
        elif choice == '4':
            print("[INFO] Retraining model...")
            if detector.train_banking_model():
                print("[OK] Model retrained successfully")
            else:
                print("[ERROR] Model retraining failed")
        
        elif choice == '5':
            print("Goodbye!")
            break
        
        else:
            print("[ERROR] Invalid option")


if __name__ == "__main__":
    main()
