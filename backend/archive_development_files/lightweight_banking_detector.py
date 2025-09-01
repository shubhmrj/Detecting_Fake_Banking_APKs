"""
Lightweight Banking APK Malware Detection Trainer
Uses only legitimate banking apps + anomaly detection
No large malware datasets required
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib
import os
from apk_analyzer import EnhancedAPKAnalyzer

class LightweightBankingDetector:
    def __init__(self):
        self.analyzer = EnhancedAPKAnalyzer()
        self.scaler = StandardScaler()
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # Expect 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.legitimate_patterns = {}
        
    def extract_key_features(self, apk_analysis):
        """Extract key features for anomaly detection"""
        features = []
        
        # Permission-based features
        total_perms = apk_analysis.get('permissions', {}).get('total_count', 0)
        critical_perms = len(apk_analysis.get('permissions', {}).get('permission_categories', {}).get('critical', []))
        dangerous_ratio = critical_perms / max(total_perms, 1)
        
        # Certificate features
        cert_info = apk_analysis.get('certificates', {})
        is_self_signed = cert_info.get('has_self_signed', False)
        cert_count = cert_info.get('certificate_count', 0)
        
        # File and metadata features
        file_size = apk_analysis.get('metadata', {}).get('file_size', 0)
        is_debuggable = apk_analysis.get('metadata', {}).get('is_debuggable', False)
        
        # API call features
        api_info = apk_analysis.get('api_calls', {})
        suspicious_api_count = len(api_info.get('suspicious_apis', []))
        total_methods = api_info.get('total_methods', 1)
        suspicious_api_ratio = suspicious_api_count / max(total_methods, 1)
        
        # Security analysis
        security_info = apk_analysis.get('security_analysis', {})
        risk_score = security_info.get('risk_score', 0)
        
        features = [
            total_perms,
            critical_perms, 
            dangerous_ratio,
            int(is_self_signed),
            cert_count,
            file_size / 1000000,  # Convert to MB
            int(is_debuggable),
            suspicious_api_count,
            suspicious_api_ratio,
            risk_score / 100  # Normalize to 0-1
        ]
        
        return np.array(features)
    
    def train_on_legitimate_apps(self, legitimate_apk_dir):
        """Train anomaly detector using only legitimate banking apps"""
        print("🏦 Training on legitimate banking apps only...")
        
        legitimate_features = []
        apk_files = [f for f in os.listdir(legitimate_apk_dir) if f.endswith('.apk')]
        
        print(f"📱 Found {len(apk_files)} legitimate banking APKs")
        
        for apk_file in apk_files:
            try:
                apk_path = os.path.join(legitimate_apk_dir, apk_file)
                print(f"⚙️ Analyzing {apk_file}...")
                
                # Analyze APK
                analysis = self.analyzer.analyze_apk(apk_path)
                
                # Extract features
                features = self.extract_key_features(analysis)
                legitimate_features.append(features)
                
            except Exception as e:
                print(f"❌ Error analyzing {apk_file}: {e}")
                continue
        
        if not legitimate_features:
            raise ValueError("No legitimate APKs could be analyzed")
        
        # Convert to numpy array
        X_legitimate = np.array(legitimate_features)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_legitimate)
        
        # Train anomaly detector (learns what's "normal")
        self.anomaly_detector.fit(X_scaled)
        
        # Store legitimate patterns for reference
        self.legitimate_patterns = {
            'mean_features': np.mean(X_legitimate, axis=0),
            'std_features': np.std(X_legitimate, axis=0),
            'feature_names': [
                'total_permissions', 'critical_permissions', 'dangerous_ratio',
                'is_self_signed', 'cert_count', 'file_size_mb', 'is_debuggable',
                'suspicious_api_count', 'suspicious_api_ratio', 'risk_score'
            ]
        }
        
        print(f"✅ Training completed on {len(legitimate_features)} legitimate apps")
        return True
    
    def predict_apk(self, apk_path):
        """Predict if APK is suspicious based on deviation from normal patterns"""
        try:
            # Analyze APK
            analysis = self.analyzer.analyze_apk(apk_path)
            
            # Extract features
            features = self.extract_key_features(analysis)
            features_scaled = self.scaler.transform([features])
            
            # Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
            is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
            
            # Calculate confidence (higher negative score = more anomalous)
            confidence = min(abs(anomaly_score) * 100, 99.9)
            
            # Detailed analysis
            deviation_analysis = self.analyze_deviations(features)
            
            result = {
                'prediction': 1 if is_anomaly else 0,
                'confidence': confidence / 100,
                'anomaly_score': anomaly_score,
                'is_suspicious': is_anomaly,
                'deviation_analysis': deviation_analysis,
                'feature_values': dict(zip(self.legitimate_patterns['feature_names'], features))
            }
            
            return result
            
        except Exception as e:
            return {'error': f"Analysis failed: {str(e)}"}
    
    def analyze_deviations(self, features):
        """Analyze how features deviate from normal banking app patterns"""
        if not self.legitimate_patterns:
            return {}
        
        mean_features = self.legitimate_patterns['mean_features']
        std_features = self.legitimate_patterns['std_features']
        feature_names = self.legitimate_patterns['feature_names']
        
        deviations = []
        for i, (feature_val, mean_val, std_val, name) in enumerate(
            zip(features, mean_features, std_features, feature_names)
        ):
            if std_val > 0:
                z_score = abs(feature_val - mean_val) / std_val
                if z_score > 2:  # More than 2 standard deviations
                    deviations.append({
                        'feature': name,
                        'value': feature_val,
                        'normal_range': f"{mean_val:.2f} ± {std_val:.2f}",
                        'deviation_score': z_score
                    })
        
        return sorted(deviations, key=lambda x: x['deviation_score'], reverse=True)
    
    def save_model(self, model_dir="models"):
        """Save trained model"""
        os.makedirs(model_dir, exist_ok=True)
        
        joblib.dump(self.anomaly_detector, f"{model_dir}/anomaly_detector.pkl")
        joblib.dump(self.scaler, f"{model_dir}/feature_scaler.pkl")
        joblib.dump(self.legitimate_patterns, f"{model_dir}/legitimate_patterns.pkl")
        
        print(f"✅ Lightweight model saved to {model_dir}/")
    
    def load_model(self, model_dir="models"):
        """Load trained model"""
        self.anomaly_detector = joblib.load(f"{model_dir}/anomaly_detector.pkl")
        self.scaler = joblib.load(f"{model_dir}/feature_scaler.pkl")
        self.legitimate_patterns = joblib.load(f"{model_dir}/legitimate_patterns.pkl")
        
        print("✅ Lightweight model loaded successfully")

def main():
    print("🚀 Lightweight Banking APK Malware Detection Trainer")
    print("=" * 55)
    print("✅ No large malware datasets required!")
    print("✅ Uses only legitimate banking apps for training")
    print("✅ Detects suspicious apps through anomaly detection")
    
    detector = LightweightBankingDetector()
    
    # Check if legitimate APKs directory exists
    legit_dir = "mp_police_datasets/legitimate/banking"
    if not os.path.exists(legit_dir):
        print(f"\n📁 Please create directory: {legit_dir}")
        print("📱 Add legitimate banking APKs to this directory")
        print("🎯 Target: 19 official banking apps from Google Play Store")
        return
    
    # Train model
    try:
        detector.train_on_legitimate_apps(legit_dir)
        detector.save_model()
        
        print("\n🎯 Model Training Complete!")
        print("✅ Your system can now detect suspicious banking apps")
        print("🔍 Test with: python lightweight_banking_detector.py --test <apk_file>")
        
    except Exception as e:
        print(f"❌ Training failed: {e}")

if __name__ == "__main__":
    main()
