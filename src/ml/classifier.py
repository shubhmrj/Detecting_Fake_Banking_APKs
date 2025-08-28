"""
Machine Learning Classification Module
Implements various ML models to classify APKs as legitimate or fake/malicious
"""

import numpy as np
import pandas as pd
import joblib
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import warnings
warnings.filterwarnings('ignore')

@dataclass
class ClassificationResult:
    """Container for classification results"""
    is_fake: bool
    confidence: float
    probability_fake: float
    probability_legitimate: float
    model_used: str
    feature_importance: Dict[str, float]

class APKClassifier:
    """Main classification class for APK authenticity detection"""
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_trained = False
        
        # Define feature columns expected by the model
        self.expected_features = [
            'permission_count', 'activity_count', 'service_count', 'receiver_count',
            'has_sms_permissions', 'has_phone_permissions', 'has_location_permissions',
            'has_camera_permissions', 'has_admin_permissions', 'has_system_alert',
            'suspicious_permission_ratio', 'certificate_count', 'has_self_signed_cert',
            'cert_validity_days', 'package_name_length', 'app_name_length',
            'has_banking_keywords', 'package_name_suspicious', 'service_to_activity_ratio',
            'receiver_to_activity_ratio'
        ]
    
    def train_model(self, training_data: pd.DataFrame, target_column: str = 'is_fake') -> Dict[str, Any]:
        """
        Train the classification model
        """
        print("Training APK classification model...")
        
        # Prepare features and target
        X = training_data[self.expected_features]
        y = training_data[target_column]
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train multiple models and select the best one
        models = {
            'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
            'GradientBoosting': GradientBoostingClassifier(random_state=42),
            'SVM': SVC(probability=True, random_state=42),
            'LogisticRegression': LogisticRegression(random_state=42)
        }
        
        best_model = None
        best_score = 0
        model_results = {}
        
        for name, model in models.items():
            # Cross-validation
            cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='roc_auc')
            avg_score = cv_scores.mean()
            
            print(f"{name}: CV AUC = {avg_score:.4f} (+/- {cv_scores.std() * 2:.4f})")
            
            model_results[name] = {
                'model': model,
                'cv_score': avg_score,
                'cv_std': cv_scores.std()
            }
            
            if avg_score > best_score:
                best_score = avg_score
                best_model = model
                self.model_name = name
        
        # Train the best model
        self.model = best_model
        self.model.fit(X_train_scaled, y_train)
        self.feature_names = self.expected_features
        self.is_trained = True
        
        # Evaluate on test set
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        test_auc = roc_auc_score(y_test, y_pred_proba)
        
        training_results = {
            'best_model': self.model_name,
            'cv_auc': best_score,
            'test_auc': test_auc,
            'classification_report': classification_report(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'feature_importance': self._get_feature_importance()
        }
        
        print(f"Best model: {self.model_name}")
        print(f"Test AUC: {test_auc:.4f}")
        
        return training_results
    
    def predict(self, features: Dict[str, Any]) -> ClassificationResult:
        """
        Predict if an APK is fake or legitimate
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train_model() first or load a trained model.")
        
        # Convert features to DataFrame
        feature_vector = self._prepare_feature_vector(features)
        
        # Scale features
        feature_vector_scaled = self.scaler.transform([feature_vector])
        
        # Make prediction
        prediction = self.model.predict(feature_vector_scaled)[0]
        probabilities = self.model.predict_proba(feature_vector_scaled)[0]
        
        # Get feature importance for this prediction
        feature_importance = self._get_feature_importance()
        
        return ClassificationResult(
            is_fake=bool(prediction),
            confidence=max(probabilities),
            probability_fake=probabilities[1] if len(probabilities) > 1 else 0.0,
            probability_legitimate=probabilities[0] if len(probabilities) > 1 else 1.0,
            model_used=getattr(self, 'model_name', 'Unknown'),
            feature_importance=feature_importance
        )
    
    def rule_based_classify(self, analysis_result) -> Dict[str, Any]:
        """
        Rule-based classification when no trained model is available
        """
        risk_score = analysis_result.risk_score
        suspicious_count = len(analysis_result.suspicious_permissions)
        
        # Simple rule-based logic
        is_fake = False
        confidence = 0.5
        
        if risk_score > 70:
            is_fake = True
            confidence = 0.9
        elif risk_score > 50:
            is_fake = True
            confidence = 0.7
        elif suspicious_count > 5:
            is_fake = True
            confidence = 0.6
        elif analysis_result.features.get('has_self_signed_cert', False):
            is_fake = True
            confidence = 0.6
        
        return {
            'is_fake': is_fake,
            'confidence': confidence,
            'method': 'rule_based',
            'risk_score': risk_score
        }
    
    def _prepare_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """
        Prepare feature vector for prediction
        """
        feature_vector = []
        
        for feature_name in self.expected_features:
            value = features.get(feature_name, 0)
            
            # Convert boolean to int
            if isinstance(value, bool):
                value = int(value)
            
            feature_vector.append(float(value))
        
        return feature_vector
    
    def _get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance from the trained model
        """
        if not self.is_trained or not hasattr(self.model, 'feature_importances_'):
            return {}
        
        importance_dict = {}
        for i, importance in enumerate(self.model.feature_importances_):
            if i < len(self.feature_names):
                importance_dict[self.feature_names[i]] = float(importance)
        
        # Sort by importance
        return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))
    
    def save_model(self, model_path: str):
        """Save the trained model"""
        if not self.is_trained:
            raise ValueError("No trained model to save")
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'model_name': getattr(self, 'model_name', 'Unknown'),
            'expected_features': self.expected_features
        }
        
        joblib.dump(model_data, model_path)
        print(f"Model saved to {model_path}")
    
    def load_model(self, model_path: str):
        """Load a trained model"""
        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        model_data = joblib.load(model_path)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.model_name = model_data.get('model_name', 'Unknown')
        self.expected_features = model_data.get('expected_features', self.expected_features)
        self.is_trained = True
        
        print(f"Model loaded from {model_path}")
    
    def generate_synthetic_training_data(self, num_samples: int = 1000) -> pd.DataFrame:
        """
        Generate synthetic training data for demonstration
        In a real scenario, you would collect actual APK samples
        """
        print(f"Generating {num_samples} synthetic training samples...")
        
        np.random.seed(42)
        data = []
        
        for i in range(num_samples):
            # Generate features for legitimate apps (50% of samples)
            if i < num_samples // 2:
                sample = self._generate_legitimate_sample()
                sample['is_fake'] = 0
            else:
                # Generate features for fake/malicious apps
                sample = self._generate_malicious_sample()
                sample['is_fake'] = 1
            
            data.append(sample)
        
        return pd.DataFrame(data)
    
    def _generate_legitimate_sample(self) -> Dict[str, Any]:
        """Generate features for a legitimate banking app"""
        return {
            'permission_count': np.random.randint(5, 15),
            'activity_count': np.random.randint(3, 10),
            'service_count': np.random.randint(1, 5),
            'receiver_count': np.random.randint(0, 3),
            'has_sms_permissions': np.random.choice([0, 1], p=[0.8, 0.2]),
            'has_phone_permissions': np.random.choice([0, 1], p=[0.7, 0.3]),
            'has_location_permissions': np.random.choice([0, 1], p=[0.6, 0.4]),
            'has_camera_permissions': np.random.choice([0, 1], p=[0.8, 0.2]),
            'has_admin_permissions': np.random.choice([0, 1], p=[0.9, 0.1]),
            'has_system_alert': np.random.choice([0, 1], p=[0.9, 0.1]),
            'suspicious_permission_ratio': np.random.uniform(0, 0.3),
            'certificate_count': 1,
            'has_self_signed_cert': 0,
            'cert_validity_days': np.random.randint(365, 3650),
            'package_name_length': np.random.randint(20, 50),
            'app_name_length': np.random.randint(10, 30),
            'has_banking_keywords': 1,
            'package_name_suspicious': 0,
            'service_to_activity_ratio': np.random.uniform(0.1, 0.5),
            'receiver_to_activity_ratio': np.random.uniform(0, 0.3)
        }
    
    def _generate_malicious_sample(self) -> Dict[str, Any]:
        """Generate features for a malicious/fake banking app"""
        return {
            'permission_count': np.random.randint(15, 35),
            'activity_count': np.random.randint(2, 8),
            'service_count': np.random.randint(3, 12),
            'receiver_count': np.random.randint(2, 8),
            'has_sms_permissions': np.random.choice([0, 1], p=[0.2, 0.8]),
            'has_phone_permissions': np.random.choice([0, 1], p=[0.3, 0.7]),
            'has_location_permissions': np.random.choice([0, 1], p=[0.4, 0.6]),
            'has_camera_permissions': np.random.choice([0, 1], p=[0.5, 0.5]),
            'has_admin_permissions': np.random.choice([0, 1], p=[0.4, 0.6]),
            'has_system_alert': np.random.choice([0, 1], p=[0.3, 0.7]),
            'suspicious_permission_ratio': np.random.uniform(0.4, 0.9),
            'certificate_count': np.random.randint(1, 3),
            'has_self_signed_cert': np.random.choice([0, 1], p=[0.3, 0.7]),
            'cert_validity_days': np.random.randint(1, 365),
            'package_name_length': np.random.randint(10, 80),
            'app_name_length': np.random.randint(5, 50),
            'has_banking_keywords': np.random.choice([0, 1], p=[0.3, 0.7]),
            'package_name_suspicious': np.random.choice([0, 1], p=[0.2, 0.8]),
            'service_to_activity_ratio': np.random.uniform(0.5, 2.0),
            'receiver_to_activity_ratio': np.random.uniform(0.3, 1.5)
        }
    
    def train_and_save_demo_model(self, model_path: str = "models/banking_apk_classifier.pkl"):
        """
        Train and save a demo model using synthetic data
        """
        # Generate synthetic training data
        training_data = self.generate_synthetic_training_data(2000)
        
        # Train the model
        results = self.train_model(training_data)
        
        # Create models directory if it doesn't exist
        Path(model_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Save the model
        self.save_model(model_path)
        
        return results
