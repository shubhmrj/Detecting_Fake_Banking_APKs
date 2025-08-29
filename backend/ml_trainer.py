"""
ML Model Training Pipeline for APK Classification
Phase 3: Machine Learning Implementation
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
import xgboost as xgb
import joblib
import json
import os
from datetime import datetime
from apk_analyzer import EnhancedAPKAnalyzer

class APKMLTrainer:
    """Machine Learning trainer for APK classification"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_columns = []
        self.model_metrics = {}
        
        # Banking app signatures (legitimate apps)
        self.legitimate_banking_signatures = {
            'com.chase.sig.android': 'Chase Mobile',
            'com.bankofamerica.android': 'Bank of America',
            'com.wellsfargo.mobile': 'Wells Fargo Mobile',
            'com.citi.citimobile': 'Citi Mobile',
            'com.usbank.mobilebanking': 'U.S. Bank',
            'com.capitalone.android': 'Capital One Mobile',
            'com.ally.MobileBanking': 'Ally Mobile Banking',
            'com.schwab.mobile': 'Charles Schwab',
            'com.tdbank.android': 'TD Bank',
            'com.regions.mobbanking': 'Regions Bank'
        }
        
        # Known malicious patterns
        self.malicious_patterns = [
            'fake', 'malicious', 'trojan', 'virus', 'malware',
            'phishing', 'scam', 'fraud', 'steal', 'hack'
        ]
    
    def extract_ml_features(self, analysis_result):
        """Extract machine learning features from APK analysis"""
        try:
            features = {}
            
            # Basic metadata features
            metadata = analysis_result.get('metadata', {})
            features['file_size'] = metadata.get('file_size', 0)
            features['min_sdk'] = metadata.get('min_sdk', 0)
            features['target_sdk'] = metadata.get('target_sdk', 0)
            features['is_signed'] = int(metadata.get('is_signed', False))
            features['is_debuggable'] = int(metadata.get('is_debuggable', False))
            features['uses_native_code'] = int(metadata.get('uses_native_code', False))
            features['library_count'] = len(metadata.get('libraries', []))
            
            # Permission features
            permissions = analysis_result.get('permissions', {})
            features['total_permissions'] = permissions.get('total_count', 0)
            features['critical_permissions'] = len(permissions.get('permission_categories', {}).get('critical', []))
            features['high_permissions'] = len(permissions.get('permission_categories', {}).get('high', []))
            features['medium_permissions'] = len(permissions.get('permission_categories', {}).get('medium', []))
            features['low_permissions'] = len(permissions.get('permission_categories', {}).get('low', []))
            
            # Specific dangerous permissions
            all_permissions = [p['name'] for p in permissions.get('permissions', [])]
            features['has_sms_permissions'] = int(any('SMS' in p for p in all_permissions))
            features['has_phone_permissions'] = int(any('PHONE' in p for p in all_permissions))
            features['has_location_permissions'] = int(any('LOCATION' in p for p in all_permissions))
            features['has_camera_permissions'] = int(any('CAMERA' in p for p in all_permissions))
            features['has_admin_permissions'] = int(any('ADMIN' in p for p in all_permissions))
            features['has_accounts_permissions'] = int(any('ACCOUNTS' in p for p in all_permissions))
            
            # Component features
            components = analysis_result.get('components', {})
            features['activity_count'] = len(components.get('activities', []))
            features['service_count'] = len(components.get('services', []))
            features['receiver_count'] = len(components.get('receivers', []))
            features['provider_count'] = len(components.get('providers', []))
            features['exported_activity_count'] = len(components.get('exported_activities', []))
            features['exported_service_count'] = len(components.get('exported_services', []))
            features['exported_receiver_count'] = len(components.get('exported_receivers', []))
            
            # Certificate features
            certificates = analysis_result.get('certificates', {})
            features['certificate_count'] = certificates.get('certificate_count', 0)
            features['has_valid_certificates'] = int(certificates.get('has_valid_certificates', False))
            features['has_self_signed'] = int(certificates.get('has_self_signed', False))
            
            # Certificate details
            cert_list = certificates.get('certificates', [])
            if cert_list and len(cert_list) > 0 and 'error' not in cert_list[0]:
                cert = cert_list[0]
                features['cert_is_expired'] = int(cert.get('is_expired', False))
                features['cert_is_self_signed'] = int(cert.get('is_self_signed', False))
                features['cert_validity_days'] = self._calculate_cert_validity_days(cert)
            else:
                features['cert_is_expired'] = 1
                features['cert_is_self_signed'] = 1
                features['cert_validity_days'] = 0
            
            # API call features
            api_calls = analysis_result.get('api_calls', {})
            features['total_methods'] = api_calls.get('total_methods', 0)
            features['suspicious_api_count'] = len(api_calls.get('suspicious_apis', []))
            features['crypto_api_count'] = len(api_calls.get('crypto_apis', []))
            features['network_api_count'] = len(api_calls.get('network_apis', []))
            features['telephony_api_count'] = len(api_calls.get('telephony_apis', []))
            features['reflection_api_count'] = len(api_calls.get('reflection_apis', []))
            
            # URL features
            urls = analysis_result.get('urls', {})
            features['http_url_count'] = len(urls.get('http_urls', []))
            features['https_url_count'] = len(urls.get('https_urls', []))
            features['suspicious_url_count'] = len(urls.get('suspicious_urls', []))
            features['ip_address_count'] = len(urls.get('ip_addresses', []))
            features['domain_count'] = len(urls.get('domains', []))
            
            # App name and package analysis
            app_name = metadata.get('app_name', '').lower()
            package_name = metadata.get('package_name', '').lower()
            
            features['has_banking_keywords'] = int(self._has_banking_keywords(app_name))
            features['suspicious_package_name'] = int(self._is_suspicious_package_name(package_name))
            features['package_name_length'] = len(package_name)
            features['app_name_length'] = len(app_name)
            
            # Legitimacy indicators
            features['is_known_legitimate'] = int(package_name in [p.lower() for p in self.legitimate_banking_signatures.keys()])
            features['has_malicious_keywords'] = int(any(pattern in app_name or pattern in package_name for pattern in self.malicious_patterns))
            
            # Risk ratios
            if features['total_permissions'] > 0:
                features['dangerous_permission_ratio'] = (features['critical_permissions'] + features['high_permissions']) / features['total_permissions']
            else:
                features['dangerous_permission_ratio'] = 0
            
            if features['total_methods'] > 0:
                features['suspicious_api_ratio'] = features['suspicious_api_count'] / features['total_methods']
            else:
                features['suspicious_api_ratio'] = 0
            
            return features
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return {}
    
    def _calculate_cert_validity_days(self, cert):
        """Calculate certificate validity period in days"""
        try:
            from datetime import datetime
            not_after = datetime.fromisoformat(cert.get('not_valid_after', '').replace('Z', '+00:00'))
            not_before = datetime.fromisoformat(cert.get('not_valid_before', '').replace('Z', '+00:00'))
            return (not_after - not_before).days
        except:
            return 0
    
    def _has_banking_keywords(self, app_name):
        """Check if app name contains banking keywords"""
        banking_keywords = [
            'bank', 'banking', 'finance', 'financial', 'payment', 'wallet', 'money',
            'credit', 'debit', 'account', 'transaction', 'transfer', 'loan', 'mortgage'
        ]
        return any(keyword in app_name.lower() for keyword in banking_keywords)
    
    def _is_suspicious_package_name(self, package_name):
        """Check if package name is suspicious"""
        if not package_name or len(package_name) < 10:
            return True
        
        suspicious_patterns = ['fake', 'test', 'temp', 'malicious', 'com.android.', 'android.']
        return any(pattern in package_name.lower() for pattern in suspicious_patterns)
    
    def generate_synthetic_training_data(self, num_samples=1000):
        """Generate synthetic training data for model training"""
        print("Generating synthetic training data...")
        
        data = []
        labels = []
        
        # Generate legitimate banking app samples
        for i in range(num_samples // 2):
            features = self._generate_legitimate_sample()
            data.append(features)
            labels.append(0)  # 0 = legitimate
        
        # Generate malicious/fake app samples
        for i in range(num_samples // 2):
            features = self._generate_malicious_sample()
            data.append(features)
            labels.append(1)  # 1 = malicious
        
        df = pd.DataFrame(data)
        df['label'] = labels
        
        return df
    
    def _generate_legitimate_sample(self):
        """Generate features for a legitimate banking app"""
        return {
            'file_size': np.random.randint(10000000, 50000000),  # 10-50MB
            'min_sdk': np.random.randint(21, 28),
            'target_sdk': np.random.randint(28, 34),
            'is_signed': 1,
            'is_debuggable': 0,
            'uses_native_code': np.random.choice([0, 1], p=[0.3, 0.7]),
            'library_count': np.random.randint(0, 5),
            'total_permissions': np.random.randint(8, 20),
            'critical_permissions': np.random.randint(0, 2),
            'high_permissions': np.random.randint(1, 4),
            'medium_permissions': np.random.randint(2, 8),
            'low_permissions': np.random.randint(2, 6),
            'has_sms_permissions': 0,
            'has_phone_permissions': np.random.choice([0, 1], p=[0.8, 0.2]),
            'has_location_permissions': np.random.choice([0, 1], p=[0.4, 0.6]),
            'has_camera_permissions': np.random.choice([0, 1], p=[0.3, 0.7]),
            'has_admin_permissions': 0,
            'has_accounts_permissions': np.random.choice([0, 1], p=[0.2, 0.8]),
            'activity_count': np.random.randint(5, 20),
            'service_count': np.random.randint(2, 10),
            'receiver_count': np.random.randint(1, 8),
            'provider_count': np.random.randint(0, 3),
            'exported_activity_count': np.random.randint(1, 5),
            'exported_service_count': np.random.randint(0, 2),
            'exported_receiver_count': np.random.randint(0, 3),
            'certificate_count': 1,
            'has_valid_certificates': 1,
            'has_self_signed': 0,
            'cert_is_expired': 0,
            'cert_is_self_signed': 0,
            'cert_validity_days': np.random.randint(365, 3650),
            'total_methods': np.random.randint(1000, 10000),
            'suspicious_api_count': np.random.randint(0, 5),
            'crypto_api_count': np.random.randint(5, 20),
            'network_api_count': np.random.randint(10, 50),
            'telephony_api_count': np.random.randint(0, 3),
            'reflection_api_count': np.random.randint(0, 5),
            'http_url_count': np.random.randint(0, 2),
            'https_url_count': np.random.randint(5, 20),
            'suspicious_url_count': 0,
            'ip_address_count': np.random.randint(0, 2),
            'domain_count': np.random.randint(1, 5),
            'has_banking_keywords': 1,
            'suspicious_package_name': 0,
            'package_name_length': np.random.randint(20, 40),
            'app_name_length': np.random.randint(10, 25),
            'is_known_legitimate': np.random.choice([0, 1], p=[0.7, 0.3]),
            'has_malicious_keywords': 0,
            'dangerous_permission_ratio': np.random.uniform(0.1, 0.3),
            'suspicious_api_ratio': np.random.uniform(0.0, 0.01)
        }
    
    def _generate_malicious_sample(self):
        """Generate features for a malicious/fake banking app"""
        return {
            'file_size': np.random.randint(1000000, 20000000),  # 1-20MB
            'min_sdk': np.random.randint(16, 25),
            'target_sdk': np.random.randint(23, 30),
            'is_signed': np.random.choice([0, 1], p=[0.3, 0.7]),
            'is_debuggable': np.random.choice([0, 1], p=[0.6, 0.4]),
            'uses_native_code': np.random.choice([0, 1], p=[0.4, 0.6]),
            'library_count': np.random.randint(0, 8),
            'total_permissions': np.random.randint(15, 35),
            'critical_permissions': np.random.randint(2, 8),
            'high_permissions': np.random.randint(3, 10),
            'medium_permissions': np.random.randint(3, 12),
            'low_permissions': np.random.randint(2, 8),
            'has_sms_permissions': np.random.choice([0, 1], p=[0.2, 0.8]),
            'has_phone_permissions': np.random.choice([0, 1], p=[0.1, 0.9]),
            'has_location_permissions': np.random.choice([0, 1], p=[0.1, 0.9]),
            'has_camera_permissions': np.random.choice([0, 1], p=[0.2, 0.8]),
            'has_admin_permissions': np.random.choice([0, 1], p=[0.4, 0.6]),
            'has_accounts_permissions': np.random.choice([0, 1], p=[0.1, 0.9]),
            'activity_count': np.random.randint(3, 15),
            'service_count': np.random.randint(1, 12),
            'receiver_count': np.random.randint(2, 15),
            'provider_count': np.random.randint(0, 5),
            'exported_activity_count': np.random.randint(2, 10),
            'exported_service_count': np.random.randint(1, 8),
            'exported_receiver_count': np.random.randint(2, 12),
            'certificate_count': np.random.randint(0, 2),
            'has_valid_certificates': np.random.choice([0, 1], p=[0.6, 0.4]),
            'has_self_signed': np.random.choice([0, 1], p=[0.3, 0.7]),
            'cert_is_expired': np.random.choice([0, 1], p=[0.4, 0.6]),
            'cert_is_self_signed': np.random.choice([0, 1], p=[0.3, 0.7]),
            'cert_validity_days': np.random.randint(1, 365),
            'total_methods': np.random.randint(500, 5000),
            'suspicious_api_count': np.random.randint(5, 25),
            'crypto_api_count': np.random.randint(0, 10),
            'network_api_count': np.random.randint(5, 30),
            'telephony_api_count': np.random.randint(3, 15),
            'reflection_api_count': np.random.randint(2, 20),
            'http_url_count': np.random.randint(2, 15),
            'https_url_count': np.random.randint(0, 10),
            'suspicious_url_count': np.random.randint(1, 8),
            'ip_address_count': np.random.randint(1, 10),
            'domain_count': np.random.randint(2, 15),
            'has_banking_keywords': np.random.choice([0, 1], p=[0.3, 0.7]),
            'suspicious_package_name': np.random.choice([0, 1], p=[0.2, 0.8]),
            'package_name_length': np.random.randint(8, 30),
            'app_name_length': np.random.randint(5, 20),
            'is_known_legitimate': 0,
            'has_malicious_keywords': np.random.choice([0, 1], p=[0.6, 0.4]),
            'dangerous_permission_ratio': np.random.uniform(0.4, 0.8),
            'suspicious_api_ratio': np.random.uniform(0.02, 0.1)
        }
    
    def train_models(self, training_data):
        """Train multiple ML models"""
        print("Training ML models...")
        
        # Prepare data
        X = training_data.drop('label', axis=1)
        y = training_data['label']
        self.feature_columns = X.columns.tolist()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        self.scalers['standard'] = scaler
        
        # Train Random Forest
        print("Training Random Forest...")
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
        rf_model.fit(X_train, y_train)
        self.models['random_forest'] = rf_model
        
        # Train XGBoost
        print("Training XGBoost...")
        xgb_model = xgb.XGBClassifier(n_estimators=100, random_state=42, max_depth=6)
        xgb_model.fit(X_train, y_train)
        self.models['xgboost'] = xgb_model
        
        # Train Gradient Boosting
        print("Training Gradient Boosting...")
        gb_model = GradientBoostingClassifier(n_estimators=100, random_state=42, max_depth=6)
        gb_model.fit(X_train_scaled, y_train)
        self.models['gradient_boosting'] = gb_model
        
        # Evaluate models
        self._evaluate_models(X_test, y_test, X_test_scaled)
        
        print("Model training completed!")
        return self.models
    
    def _evaluate_models(self, X_test, y_test, X_test_scaled):
        """Evaluate trained models"""
        print("\nModel Evaluation Results:")
        print("=" * 50)
        
        for model_name, model in self.models.items():
            if model_name == 'gradient_boosting':
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
            else:
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            
            # Calculate metrics
            accuracy = model.score(X_test_scaled if model_name == 'gradient_boosting' else X_test, y_test)
            auc_score = roc_auc_score(y_test, y_pred_proba)
            
            self.model_metrics[model_name] = {
                'accuracy': accuracy,
                'auc_score': auc_score,
                'classification_report': classification_report(y_test, y_pred, output_dict=True)
            }
            
            print(f"\n{model_name.upper()}:")
            print(f"Accuracy: {accuracy:.4f}")
            print(f"AUC Score: {auc_score:.4f}")
            print(f"Classification Report:")
            print(classification_report(y_test, y_pred))
    
    def predict(self, features, model_name='random_forest'):
        """Make prediction using trained model"""
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not found")
        
        model = self.models[model_name]
        
        # Ensure features are in correct order
        feature_vector = [features.get(col, 0) for col in self.feature_columns]
        feature_array = np.array(feature_vector).reshape(1, -1)
        
        # Scale if needed
        if model_name == 'gradient_boosting':
            feature_array = self.scalers['standard'].transform(feature_array)
        
        # Make prediction
        prediction = model.predict(feature_array)[0]
        prediction_proba = model.predict_proba(feature_array)[0]
        
        return {
            'prediction': int(prediction),
            'probability_legitimate': float(prediction_proba[0]),
            'probability_malicious': float(prediction_proba[1]),
            'confidence': float(max(prediction_proba)),
            'model_used': model_name
        }
    
    def get_feature_importance(self, model_name='random_forest'):
        """Get feature importance from trained model"""
        if model_name not in self.models:
            return {}
        
        model = self.models[model_name]
        
        if hasattr(model, 'feature_importances_'):
            importance_dict = dict(zip(self.feature_columns, model.feature_importances_))
            # Sort by importance
            sorted_importance = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
            return dict(sorted_importance)
        
        return {}
    
    def save_models(self, model_dir='models'):
        """Save trained models and scalers"""
        os.makedirs(model_dir, exist_ok=True)
        
        # Save models
        for model_name, model in self.models.items():
            model_path = os.path.join(model_dir, f'{model_name}_model.pkl')
            joblib.dump(model, model_path)
            print(f"Saved {model_name} model to {model_path}")
        
        # Save scalers
        for scaler_name, scaler in self.scalers.items():
            scaler_path = os.path.join(model_dir, f'{scaler_name}_scaler.pkl')
            joblib.dump(scaler, scaler_path)
        
        # Save feature columns and metrics
        metadata = {
            'feature_columns': self.feature_columns,
            'model_metrics': self.model_metrics,
            'training_timestamp': datetime.now().isoformat()
        }
        
        with open(os.path.join(model_dir, 'model_metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Models and metadata saved to {model_dir}/")
    
    def load_models(self, model_dir='models'):
        """Load trained models and scalers"""
        # Load metadata
        metadata_path = os.path.join(model_dir, 'model_metadata.json')
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
                self.feature_columns = metadata['feature_columns']
                self.model_metrics = metadata['model_metrics']
        
        # Load models
        for model_file in os.listdir(model_dir):
            if model_file.endswith('_model.pkl'):
                model_name = model_file.replace('_model.pkl', '')
                model_path = os.path.join(model_dir, model_file)
                self.models[model_name] = joblib.load(model_path)
                print(f"Loaded {model_name} model from {model_path}")
        
        # Load scalers
        for scaler_file in os.listdir(model_dir):
            if scaler_file.endswith('_scaler.pkl'):
                scaler_name = scaler_file.replace('_scaler.pkl', '')
                scaler_path = os.path.join(model_dir, scaler_file)
                self.scalers[scaler_name] = joblib.load(scaler_path)
        
        print(f"Models loaded from {model_dir}/")

if __name__ == '__main__':
    # Example usage
    trainer = APKMLTrainer()
    
    # Generate synthetic training data
    training_data = trainer.generate_synthetic_training_data(num_samples=2000)
    
    # Train models
    models = trainer.train_models(training_data)
    
    # Save models
    trainer.save_models()
    
    # Show feature importance
    print("\nTop 10 Most Important Features:")
    importance = trainer.get_feature_importance('random_forest')
    for i, (feature, score) in enumerate(list(importance.items())[:10]):
        print(f"{i+1}. {feature}: {score:.4f}")
