"""
Banking APK Model Training with Anomaly Detection
Trains on 8 legitimate banking APKs from MP Police dataset
"""

import os
import pandas as pd
import numpy as np
import zipfile
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report
import joblib
import json
from datetime import datetime
try:
    from androguard.core.bytecodes.apk import APK
    print("[OK] androguard imported successfully")
except ImportError:
    print("Warning: androguard not installed. Install with: pip install androguard")
    APK = None
from analysis.apk_analyzer import APKAnalyzer

class BankingAPKTrainer:
    def __init__(self):
        self.analyzer = APKAnalyzer()
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% outliers
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.feature_columns = []
        self.legitimate_baseline = {}

    def extract_features_from_banking_apks(self):
        """Extract features from legitimate banking APKs"""
        banking_dir = os.path.join(os.path.dirname(__file__), "mp_police_datasets", "legitimate", "banking")
        features_list = []

        print("Processing Legitimate Banking APKs...")
        print("=" * 50)

        if not os.path.exists(banking_dir):
            print(f"ERROR: Directory not found: {banking_dir}")
            return []

        apk_files = [f for f in os.listdir(banking_dir) if f.endswith('.apk')]
        print(f"Found {len(apk_files)} banking APKs")

        for i, filename in enumerate(apk_files, 1):
            apk_path = os.path.join(banking_dir, filename)
            print(f"\n[{i}/{len(apk_files)}] Analyzing {filename}...")

            # First validate APK file
            if not zipfile.is_zipfile(apk_path):
                print(f"SKIPPED: {filename} is not a valid APK file (corrupted or wrong format)")
                continue

            try:
                # Analyze APK
                analysis = self.analyzer.analyze(apk_path)

                if analysis:
                    # Extract features
                    features = self.extract_numerical_features(analysis, filename)
                    features_list.append(features)
                    print(f"SUCCESS: Successfully processed {filename}")
                    print(f"   Extracted {len(features)-1} features")
                else:
                    print(f"ERROR: Error analyzing {filename}")

            except Exception as e:
                print(f"ERROR: Exception processing {filename}: {str(e)}")

        print(f"\nSuccessfully processed {len(features_list)}/{len(apk_files)} APKs")
        return features_list

    def extract_numerical_features(self, analysis, filename):
        """Extract comprehensive numerical features from APK analysis"""
        features = {'filename': filename}

        # Basic APK information
        features['version_code'] = getattr(analysis, 'version_code', 0)
        features['package_name_length'] = len(getattr(analysis, 'package_name', ''))
        features['app_name_length'] = len(getattr(analysis, 'app_name', ''))

        # Permission analysis
        permissions = getattr(analysis, 'permissions', [])
        features['total_permissions'] = len(permissions)

        suspicious_permissions = getattr(analysis, 'suspicious_permissions', [])
        features['suspicious_permissions'] = len(suspicious_permissions)

        # Component analysis
        activities = getattr(analysis, 'activities', [])
        services = getattr(analysis, 'services', [])
        receivers = getattr(analysis, 'receivers', [])

        features['activity_count'] = len(activities)
        features['service_count'] = len(services)
        features['receiver_count'] = len(receivers)
        features['provider_count'] = 0  # Not available in current structure

        # Certificate analysis
        certificates = getattr(analysis, 'certificates', [])
        features['certificate_count'] = len(certificates)
        features['has_valid_certificates'] = int(len(certificates) > 0)

        # Check for self-signed certificates
        self_signed_count = 0
        for cert in certificates:
            if isinstance(cert, dict) and cert.get('is_self_signed', False):
                self_signed_count += 1
        features['has_self_signed'] = int(self_signed_count > 0)

        # Risk score from analysis
        features['risk_score'] = getattr(analysis, 'risk_score', 0)

        # Additional features from analysis.features if available
        analysis_features = getattr(analysis, 'features', {})
        if isinstance(analysis_features, dict):
            features.update({
                'total_methods': analysis_features.get('total_methods', 0),
                'suspicious_apis': analysis_features.get('suspicious_apis', 0),
                'crypto_apis': analysis_features.get('crypto_apis', 0),
                'network_apis': analysis_features.get('network_apis', 0),
                'telephony_apis': analysis_features.get('telephony_apis', 0)
            })
        else:
            # Default values if features not available
            features.update({
                'total_methods': 100,
                'suspicious_apis': 0,
                'crypto_apis': 5,
                'network_apis': 10,
                'telephony_apis': 0
            })

        # URL and network analysis (defaults since not in current structure)
        features['http_urls'] = 0
        features['https_urls'] = 5  # Assume banking apps use HTTPS
        features['suspicious_urls'] = 0
        features['ip_addresses'] = 0

        # Banking-specific features
        package_name = getattr(analysis, 'package_name', '').lower()
        banking_keywords = ['bank', 'banking', 'finance', 'payment', 'wallet']
        features['has_banking_keywords'] = int(any(keyword in package_name for keyword in banking_keywords))
        features['suspicious_package_name'] = int('fake' in package_name or 'malware' in package_name)

        # Calculate ratios for better anomaly detection
        if features['total_permissions'] > 0:
            features['dangerous_permission_ratio'] = features['suspicious_permissions'] / features['total_permissions']
        else:
            features['dangerous_permission_ratio'] = 0

        if features['total_methods'] > 0:
            features['suspicious_api_ratio'] = features['suspicious_apis'] / features['total_methods']
        else:
            features['suspicious_api_ratio'] = 0

        return features

    def train_anomaly_detection_model(self):
        """Train anomaly detection model on legitimate banking APKs"""
        print("\nTraining Anomaly Detection Model...")
        print("=" * 50)

        # Extract features from banking APKs
        features_list = self.extract_features_from_banking_apks()

        if len(features_list) < 2:
            print("ERROR: Need at least 2 APKs for training. Found:", len(features_list))
            return False

        # Convert to DataFrame
        df = pd.DataFrame(features_list)

        # Remove filename column for training
        feature_columns = [col for col in df.columns if col != 'filename']
        self.feature_columns = feature_columns

        # Ensure all data is numeric
        X = df[feature_columns].fillna(0)

        # Convert all columns to numeric, handling any string values
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)

        print(f"Training data shape: {X.shape}")
        print(f"Features: {len(feature_columns)}")

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train isolation forest
        self.isolation_forest.fit(X_scaled)

        # Calculate baseline statistics for legitimate apps
        try:
            self.legitimate_baseline = {
                'mean': X.mean().to_dict(),
                'std': X.std().to_dict(),
                'min': X.min().to_dict(),
                'max': X.max().to_dict()
            }
        except Exception as e:
            print(f"WARNING: Error calculating baseline statistics: {e}")
            # Provide default baseline if calculation fails
            self.legitimate_baseline = {
                'mean': {col: 0.0 for col in feature_columns},
                'std': {col: 1.0 for col in feature_columns},
                'min': {col: 0.0 for col in feature_columns},
                'max': {col: 1.0 for col in feature_columns}
            }

        # Evaluate model
        anomaly_scores = self.isolation_forest.decision_function(X_scaled)
        predictions = self.isolation_forest.predict(X_scaled)

        print(f"\nModel Training Results:")
        print(f"   Legitimate APKs: {len(features_list)}")
        print(f"   Features extracted: {len(feature_columns)}")
        print(f"   Anomaly scores range: {anomaly_scores.min():.3f} to {anomaly_scores.max():.3f}")
        print(f"   Normal predictions: {np.sum(predictions == 1)}")
        print(f"   Anomaly predictions: {np.sum(predictions == -1)}")

        return True

    def save_model(self):
        """Save trained model and metadata"""
        model_dir = "models"
        os.makedirs(model_dir, exist_ok=True)

        # Save model components
        joblib.dump(self.isolation_forest, f"{model_dir}/banking_anomaly_model.pkl")
        joblib.dump(self.scaler, f"{model_dir}/banking_scaler.pkl")

        # Save metadata
        metadata = {
            'model_type': 'anomaly_detection',
            'algorithm': 'isolation_forest',
            'feature_columns': self.feature_columns,
            'legitimate_baseline': self.legitimate_baseline,
            'training_timestamp': datetime.now().isoformat(),
            'contamination': 0.1,
            'n_estimators': 100
        }

        with open(f"{model_dir}/banking_model_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"\nModel saved to {model_dir}/")
        print("   banking_anomaly_model.pkl")
        print("   banking_scaler.pkl")
        print("   banking_model_metadata.json")

    def test_model_with_sample(self, apk_path):
        """Test trained model with a sample APK"""
        print(f"\nTesting model with: {os.path.basename(apk_path)}")

        try:
            # Analyze APK
            analysis = self.analyzer.analyze(apk_path)

            if not analysis:
                print(f"ERROR: Analysis failed")
                return None

            # Extract features
            features = self.extract_numerical_features(analysis, os.path.basename(apk_path))

            # Prepare for prediction
            feature_values = [features.get(col, 0) for col in self.feature_columns]
            X_test = np.array(feature_values).reshape(1, -1)
            X_test_scaled = self.scaler.transform(X_test)

            # Predict
            prediction = self.isolation_forest.predict(X_test_scaled)[0]
            anomaly_score = self.isolation_forest.decision_function(X_test_scaled)[0]

            # Interpret results
            is_legitimate = prediction == 1
            confidence = abs(anomaly_score)

            print(f"Results:")
            print(f"   Prediction: {'LEGITIMATE' if is_legitimate else 'SUSPICIOUS'}")
            print(f"   Anomaly Score: {anomaly_score:.3f}")
            print(f"   Confidence: {confidence:.3f}")

            return {
                'is_legitimate': is_legitimate,
                'anomaly_score': anomaly_score,
                'confidence': confidence,
                'features': features
            }

        except Exception as e:
            print(f"ERROR: Testing error: {str(e)}")
            return None

def main():
    """Main training pipeline"""
    print("Banking APK Anomaly Detection Training")
    print("=" * 60)

    trainer = BankingAPKTrainer()

    # Train model
    if trainer.train_anomaly_detection_model():
        # Save model
        trainer.save_model()

        print("\nTraining completed successfully!")
        print("\nNext steps:")
        print("   1. Test model with: python test_banking_model.py")
        print("   2. Start web interface: python enhanced_app.py")
        print("   3. Upload APKs through frontend at http://localhost:3000")

        return True
    else:
        print("ERROR: Training failed!")
        return False

if __name__ == "__main__":
    main()
