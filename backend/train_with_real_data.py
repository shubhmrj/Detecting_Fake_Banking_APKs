"""
Train ML Models with Real Banking APK Data
Uses legitimate banking APKs from MP Police dataset
"""

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import joblib
import json
from datetime import datetime
from analysis.enhanced_analyzer import EnhancedAPKAnalyzer

class RealDataTrainer:
    def __init__(self):
        self.analyzer = EnhancedAPKAnalyzer()
        self.models = {}
        self.scaler = StandardScaler()
        self.feature_columns = []
        
    def extract_features_from_apks(self, apk_directory, label):
        """Extract features from APK files in directory"""
        features_list = []
        
        print(f"Processing APKs in {apk_directory} with label '{label}'...")
        
        for filename in os.listdir(apk_directory):
            if filename.endswith('.apk'):
                apk_path = os.path.join(apk_directory, filename)
                print(f"Analyzing {filename}...")
                
                try:
                    # Analyze APK
                    analysis = self.analyzer.analyze_apk(apk_path)
                    
                    if 'error' not in analysis:
                        # Extract numerical features
                        features = self.extract_numerical_features(analysis)
                        features['label'] = label
                        features['filename'] = filename
                        features_list.append(features)
                        print(f"✓ Successfully processed {filename}")
                    else:
                        print(f"✗ Error analyzing {filename}: {analysis['error']}")
                        
                except Exception as e:
                    print(f"✗ Exception processing {filename}: {str(e)}")
                    
        return features_list
    
    def extract_numerical_features(self, analysis):
        """Extract numerical features from APK analysis"""
        features = {}
        
        # Basic metadata features
        metadata = analysis.get('metadata', {})
        features['file_size'] = metadata.get('file_size', 0)
        features['min_sdk'] = metadata.get('min_sdk', 0)
        features['target_sdk'] = metadata.get('target_sdk', 0)
        features['version_code'] = metadata.get('version_code', 0)
        features['is_signed'] = int(metadata.get('is_signed', False))
        features['is_debuggable'] = int(metadata.get('is_debuggable', False))
        features['uses_native_code'] = int(metadata.get('uses_native_code', False))
        
        # Permission features
        permissions = analysis.get('permissions', {})
        features['total_permissions'] = permissions.get('total_count', 0)
        features['suspicious_permissions_count'] = len(permissions.get('suspicious_permissions', []))
        features['critical_permissions_count'] = len(permissions.get('permission_categories', {}).get('critical', []))
        features['high_permissions_count'] = len(permissions.get('permission_categories', {}).get('high', []))
        
        # Certificate features
        certificates = analysis.get('certificates', {})
        features['certificate_count'] = certificates.get('certificate_count', 0)
        features['has_valid_certificates'] = int(certificates.get('has_valid_certificates', False))
        features['has_self_signed'] = int(certificates.get('has_self_signed', False))
        
        # API call features
        api_calls = analysis.get('api_calls', {})
        features['total_methods'] = api_calls.get('total_methods', 0)
        features['suspicious_apis_count'] = len(api_calls.get('suspicious_apis', []))
        features['crypto_apis_count'] = len(api_calls.get('crypto_apis', []))
        features['network_apis_count'] = len(api_calls.get('network_apis', []))
        features['telephony_apis_count'] = len(api_calls.get('telephony_apis', []))
        features['reflection_apis_count'] = len(api_calls.get('reflection_apis', []))
        
        # URL features
        urls = analysis.get('urls', {})
        features['http_urls_count'] = len(urls.get('http_urls', []))
        features['https_urls_count'] = len(urls.get('https_urls', []))
        features['suspicious_urls_count'] = len(urls.get('suspicious_urls', []))
        features['ip_addresses_count'] = len(urls.get('ip_addresses', []))
        
        # Security analysis features
        security = analysis.get('security_analysis', {})
        features['risk_score'] = security.get('risk_score', 0)
        features['is_suspicious'] = int(security.get('is_suspicious', False))
        
        return features
    
    def train_models(self):
        """Train models with real APK data"""
        print("Starting ML model training with real banking APK data...")
        
        # Collect features from legitimate banking APKs
        legitimate_dir = os.path.join(os.path.dirname(__file__), "mp_police_datasets", "legitimate", "banking")
        legitimate_features = self.extract_features_from_apks(legitimate_dir, 0)  # 0 = legitimate
        
        print(f"Extracted features from {len(legitimate_features)} legitimate banking APKs")
        
        # For now, we'll use synthetic malicious data since we don't have real malware
        # In production, you would add real malware samples here
        malicious_features = self.generate_synthetic_malicious_features(len(legitimate_features))
        
        # Combine all features
        all_features = legitimate_features + malicious_features
        
        if len(all_features) < 2:
            print("Not enough data to train models. Need at least 2 samples.")
            return
        
        # Convert to DataFrame
        df = pd.DataFrame(all_features)
        
        # Separate features and labels
        feature_cols = [col for col in df.columns if col not in ['label', 'filename']]
        X = df[feature_cols]
        y = df['label']
        
        self.feature_columns = feature_cols
        
        # Handle missing values
        X = X.fillna(0)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Train Random Forest
        print("Training Random Forest model...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        rf_model.fit(X_train, y_train)
        
        # Train Gradient Boosting
        print("Training Gradient Boosting model...")
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=6,
            random_state=42
        )
        gb_model.fit(X_train, y_train)
        
        # Evaluate models
        rf_score = rf_model.score(X_test, y_test)
        gb_score = gb_model.score(X_test, y_test)
        
        print(f"Random Forest Accuracy: {rf_score:.3f}")
        print(f"Gradient Boosting Accuracy: {gb_score:.3f}")
        
        # Store models
        self.models['random_forest'] = rf_model
        self.models['gradient_boosting'] = gb_model
        
        # Save models
        self.save_models()
        
        print("✓ Model training completed successfully!")
        
        return {
            'random_forest_accuracy': rf_score,
            'gradient_boosting_accuracy': gb_score,
            'feature_count': len(feature_cols),
            'training_samples': len(all_features)
        }
    
    def generate_synthetic_malicious_features(self, count):
        """Generate synthetic malicious APK features for training"""
        malicious_features = []
        
        for i in range(count):
            features = {
                'file_size': np.random.randint(1000000, 50000000),
                'min_sdk': np.random.randint(15, 25),
                'target_sdk': np.random.randint(25, 33),
                'version_code': np.random.randint(1, 100),
                'is_signed': np.random.choice([0, 1], p=[0.3, 0.7]),  # Some unsigned
                'is_debuggable': np.random.choice([0, 1], p=[0.7, 0.3]),  # More debuggable
                'uses_native_code': np.random.choice([0, 1], p=[0.4, 0.6]),
                
                # Higher suspicious activity for malicious
                'total_permissions': np.random.randint(15, 50),
                'suspicious_permissions_count': np.random.randint(5, 20),
                'critical_permissions_count': np.random.randint(2, 10),
                'high_permissions_count': np.random.randint(3, 15),
                
                # Certificate issues
                'certificate_count': np.random.randint(0, 3),
                'has_valid_certificates': np.random.choice([0, 1], p=[0.6, 0.4]),
                'has_self_signed': np.random.choice([0, 1], p=[0.3, 0.7]),
                
                # API calls
                'total_methods': np.random.randint(500, 5000),
                'suspicious_apis_count': np.random.randint(10, 50),
                'crypto_apis_count': np.random.randint(0, 20),
                'network_apis_count': np.random.randint(5, 30),
                'telephony_apis_count': np.random.randint(2, 15),
                'reflection_apis_count': np.random.randint(1, 10),
                
                # URLs
                'http_urls_count': np.random.randint(0, 20),
                'https_urls_count': np.random.randint(0, 10),
                'suspicious_urls_count': np.random.randint(1, 10),
                'ip_addresses_count': np.random.randint(0, 5),
                
                # High risk scores for malicious
                'risk_score': np.random.randint(60, 100),
                'is_suspicious': 1,
                
                'label': 1,  # 1 = malicious
                'filename': f'synthetic_malicious_{i}.apk'
            }
            malicious_features.append(features)
        
        return malicious_features
    
    def save_models(self):
        """Save trained models and metadata"""
        models_dir = "models"
        os.makedirs(models_dir, exist_ok=True)
        
        # Save models
        for name, model in self.models.items():
            joblib.dump(model, f"{models_dir}/{name}_model.pkl")
        
        # Save scaler
        joblib.dump(self.scaler, f"{models_dir}/scaler.pkl")
        
        # Save metadata
        metadata = {
            'feature_columns': self.feature_columns,
            'training_date': datetime.now().isoformat(),
            'model_types': list(self.models.keys()),
            'feature_count': len(self.feature_columns)
        }
        
        with open(f"{models_dir}/model_metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"✓ Models saved to {models_dir}/")

if __name__ == "__main__":
    trainer = RealDataTrainer()
    results = trainer.train_models()
    print("\nTraining Results:")
    for key, value in results.items():
        print(f"{key}: {value}")
