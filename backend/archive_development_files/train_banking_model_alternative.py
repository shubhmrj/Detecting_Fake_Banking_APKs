"""
Alternative Banking APK Model Training - No Androguard Required
Uses synthetic legitimate banking APK features for training
"""

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import json
from datetime import datetime

class AlternativeBankingAPKTrainer:
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expect 10% outliers
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.feature_columns = []
        self.legitimate_baseline = {}
    
    def generate_legitimate_banking_features(self):
        """Generate realistic legitimate banking APK features based on known patterns"""
        print("Generating legitimate banking APK feature patterns...")
        print("=" * 50)
        
        # Based on analysis of real banking apps, create realistic feature sets
        legitimate_samples = []
        
        # Sample 1: Large bank app (like SBI, HDFC)
        sample1 = {
            'version_code': 12045,
            'package_name_length': 25,
            'app_name_length': 15,
            'total_permissions': 28,
            'suspicious_permissions': 8,
            'activity_count': 45,
            'service_count': 12,
            'receiver_count': 8,
            'provider_count': 2,
            'certificate_count': 1,
            'has_valid_certificates': 1,
            'has_self_signed': 0,
            'risk_score': 25,
            'total_methods': 8500,
            'suspicious_apis': 15,
            'crypto_apis': 25,
            'network_apis': 45,
            'telephony_apis': 5,
            'http_urls': 2,
            'https_urls': 15,
            'suspicious_urls': 0,
            'ip_addresses': 3,
            'has_banking_keywords': 1,
            'suspicious_package_name': 0,
            'dangerous_permission_ratio': 0.29,
            'suspicious_api_ratio': 0.0018
        }
        
        # Sample 2: Medium bank app (like Axis, Canara)
        sample2 = {
            'version_code': 8032,
            'package_name_length': 22,
            'app_name_length': 12,
            'total_permissions': 24,
            'suspicious_permissions': 6,
            'activity_count': 38,
            'service_count': 10,
            'receiver_count': 6,
            'provider_count': 1,
            'certificate_count': 1,
            'has_valid_certificates': 1,
            'has_self_signed': 0,
            'risk_score': 20,
            'total_methods': 6800,
            'suspicious_apis': 12,
            'crypto_apis': 20,
            'network_apis': 35,
            'telephony_apis': 3,
            'http_urls': 1,
            'https_urls': 12,
            'suspicious_urls': 0,
            'ip_addresses': 2,
            'has_banking_keywords': 1,
            'suspicious_package_name': 0,
            'dangerous_permission_ratio': 0.25,
            'suspicious_api_ratio': 0.0018
        }
        
        # Sample 3: Regional bank app
        sample3 = {
            'version_code': 5021,
            'package_name_length': 28,
            'app_name_length': 18,
            'total_permissions': 20,
            'suspicious_permissions': 5,
            'activity_count': 32,
            'service_count': 8,
            'receiver_count': 5,
            'provider_count': 1,
            'certificate_count': 1,
            'has_valid_certificates': 1,
            'has_self_signed': 0,
            'risk_score': 18,
            'total_methods': 5200,
            'suspicious_apis': 8,
            'crypto_apis': 18,
            'network_apis': 28,
            'telephony_apis': 2,
            'http_urls': 0,
            'https_urls': 10,
            'suspicious_urls': 0,
            'ip_addresses': 1,
            'has_banking_keywords': 1,
            'suspicious_package_name': 0,
            'dangerous_permission_ratio': 0.25,
            'suspicious_api_ratio': 0.0015
        }
        
        # Sample 4: Payment/Wallet app
        sample4 = {
            'version_code': 9876,
            'package_name_length': 20,
            'app_name_length': 10,
            'total_permissions': 22,
            'suspicious_permissions': 7,
            'activity_count': 28,
            'service_count': 6,
            'receiver_count': 4,
            'provider_count': 1,
            'certificate_count': 1,
            'has_valid_certificates': 1,
            'has_self_signed': 0,
            'risk_score': 22,
            'total_methods': 4500,
            'suspicious_apis': 10,
            'crypto_apis': 15,
            'network_apis': 25,
            'telephony_apis': 4,
            'http_urls': 1,
            'https_urls': 8,
            'suspicious_urls': 0,
            'ip_addresses': 2,
            'has_banking_keywords': 1,
            'suspicious_package_name': 0,
            'dangerous_permission_ratio': 0.32,
            'suspicious_api_ratio': 0.0022
        }
        
        # Sample 5: Corporate banking app
        sample5 = {
            'version_code': 15678,
            'package_name_length': 30,
            'app_name_length': 20,
            'total_permissions': 32,
            'suspicious_permissions': 10,
            'activity_count': 55,
            'service_count': 15,
            'receiver_count': 10,
            'provider_count': 3,
            'certificate_count': 1,
            'has_valid_certificates': 1,
            'has_self_signed': 0,
            'risk_score': 30,
            'total_methods': 12000,
            'suspicious_apis': 20,
            'crypto_apis': 35,
            'network_apis': 60,
            'telephony_apis': 8,
            'http_urls': 3,
            'https_urls': 20,
            'suspicious_urls': 0,
            'ip_addresses': 4,
            'has_banking_keywords': 1,
            'suspicious_package_name': 0,
            'dangerous_permission_ratio': 0.31,
            'suspicious_api_ratio': 0.0017
        }
        
        legitimate_samples = [sample1, sample2, sample3, sample4, sample5]
        
        print(f"Generated {len(legitimate_samples)} legitimate banking APK feature sets")
        return legitimate_samples
    
    def train_anomaly_detection_model(self):
        """Train anomaly detection model using generated legitimate features"""
        print("\nTraining Anomaly Detection Model...")
        print("=" * 50)
        
        # Generate legitimate banking features
        features_list = self.generate_legitimate_banking_features()
        
        if len(features_list) < 2:
            print("ERROR: Need at least 2 samples for training. Found:", len(features_list))
            return False
        
        # Convert to DataFrame
        df = pd.DataFrame(features_list)
        
        # Get feature columns
        self.feature_columns = list(df.columns)
        
        # Ensure all data is numeric
        X = df.fillna(0)
        
        # Convert all columns to numeric
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
        
        print(f"Training data shape: {X.shape}")
        print(f"Features: {len(self.feature_columns)}")
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train isolation forest
        self.isolation_forest.fit(X_scaled)
        
        # Calculate baseline statistics for legitimate apps
        self.legitimate_baseline = {
            'mean': X.mean().to_dict(),
            'std': X.std().to_dict(),
            'min': X.min().to_dict(),
            'max': X.max().to_dict()
        }
        
        # Evaluate model
        anomaly_scores = self.isolation_forest.decision_function(X_scaled)
        predictions = self.isolation_forest.predict(X_scaled)
        
        print(f"\nModel Training Results:")
        print(f"   Legitimate samples: {len(features_list)}")
        print(f"   Features extracted: {len(self.feature_columns)}")
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
            'n_estimators': 100,
            'training_method': 'synthetic_legitimate_features',
            'note': 'Trained using realistic banking APK feature patterns'
        }
        
        with open(f"{model_dir}/banking_model_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"\nModel saved to {model_dir}/")
        print("   banking_anomaly_model.pkl")
        print("   banking_scaler.pkl")
        print("   banking_model_metadata.json")
    
    def predict_apk_features(self, features_dict):
        """Predict if APK features indicate legitimate or suspicious banking app"""
        try:
            # Prepare feature vector
            feature_values = [features_dict.get(col, 0) for col in self.feature_columns]
            X_test = np.array(feature_values).reshape(1, -1)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Predict
            prediction = self.isolation_forest.predict(X_test_scaled)[0]
            anomaly_score = self.isolation_forest.decision_function(X_test_scaled)[0]
            
            # Interpret results
            is_legitimate = prediction == 1
            confidence = abs(anomaly_score)
            
            return {
                'is_legitimate': is_legitimate,
                'anomaly_score': float(anomaly_score),
                'confidence': float(confidence),
                'prediction': 'LEGITIMATE' if is_legitimate else 'SUSPICIOUS'
            }
            
        except Exception as e:
            print(f"ERROR: Prediction error: {str(e)}")
            return None

def main():
    """Main training pipeline"""
    print("Alternative Banking APK Anomaly Detection Training")
    print("=" * 60)
    print("Using synthetic legitimate banking APK features")
    print("This approach doesn't require androguard for training")
    print()
    
    trainer = AlternativeBankingAPKTrainer()
    
    # Train model
    if trainer.train_anomaly_detection_model():
        # Save model
        trainer.save_model()
        
        print("\nTraining completed successfully!")
        print("\nModel Features:")
        print(f"   - Trained on {len(trainer.feature_columns)} features")
        print("   - Uses realistic banking APK patterns")
        print("   - Ready for integration with Flask API")
        print("\nNext steps:")
        print("   1. Start web interface: python enhanced_app.py")
        print("   2. Upload APKs through frontend for analysis")
        print("   3. Model will detect anomalies in banking APKs")
        
        return True
    else:
        print("ERROR: Training failed!")
        return False

if __name__ == "__main__":
    main()
