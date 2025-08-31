"""
Test Banking APK Anomaly Detection Model
Comprehensive testing for trained model and system integration
"""

import os
import json
import joblib
import numpy as np
from datetime import datetime
from analysis.enhanced_analyzer import EnhancedAPKAnalyzer

class BankingModelTester:
    def __init__(self):
        self.analyzer = EnhancedAPKAnalyzer()
        self.model_loaded = False
        self.load_trained_model()

    def load_trained_model(self):
        """Load the trained anomaly detection model"""
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

                print("✅ Banking anomaly detection model loaded successfully")
                print(f"📊 Model trained on: {self.model_metadata['training_timestamp']}")
                print(f"🔢 Features: {len(self.feature_columns)}")

            else:
                print("❌ Model files not found. Run train_banking_model.py first")
                print("   Expected files:")
                print(f"   - {model_path}")
                print(f"   - {scaler_path}")
                print(f"   - {metadata_path}")

        except Exception as e:
            print(f"❌ Error loading model: {e}")
            self.model_loaded = False

    def extract_features_for_prediction(self, analysis):
        """Extract features for model prediction (same as training)"""
        features = {}

        # File metadata
        metadata = analysis.get('metadata', {})
        features['file_size'] = metadata.get('file_size', 0) / (1024 * 1024)  # MB
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

    def test_single_apk(self, apk_path):
        """Test model with a single APK file"""
        if not self.model_loaded:
            print("❌ Model not loaded. Cannot perform testing.")
            return None

        print(f"\n🧪 Testing APK: {os.path.basename(apk_path)}")
        print("=" * 60)

        try:
            # Analyze APK
            print("🔍 Analyzing APK...")
            analysis = self.analyzer.analyze_apk(apk_path)

            if 'error' in analysis:
                print(f"❌ Analysis error: {analysis['error']}")
                return None

            # Extract features
            print("📊 Extracting features...")
            features = self.extract_features_for_prediction(analysis)

            # Prepare for prediction
            feature_values = [features.get(col, 0) for col in self.feature_columns]
            X_test = np.array(feature_values).reshape(1, -1)
            X_test_scaled = self.scaler.transform(X_test)

            # Predict
            print("🤖 Running anomaly detection...")
            prediction = self.isolation_forest.predict(X_test_scaled)[0]
            anomaly_score = self.isolation_forest.decision_function(X_test_scaled)[0]

            # Interpret results
            is_legitimate = prediction == 1
            confidence = abs(anomaly_score)
            risk_percentage = max(0, -anomaly_score * 100) if anomaly_score < 0 else 0

            # Display results
            print("\n📋 ANALYSIS RESULTS:")
            print("=" * 30)

            status = "✅ LEGITIMATE" if is_legitimate else "🚨 SUSPICIOUS"
            print(f"🎯 Status: {status}")
            print(f"📈 Anomaly Score: {anomaly_score:.4f}")
            print(f"🔒 Confidence: {confidence:.4f}")
            print(f"⚠️ Risk Level: {risk_percentage:.1f}%")

            # Show key features
            print(f"\n📊 KEY FEATURES:")
            print(f"   📱 Package: {analysis.get('metadata', {}).get('package_name', 'Unknown')}")
            print(f"   📦 App Name: {analysis.get('metadata', {}).get('app_name', 'Unknown')}")
            print(f"   📏 File Size: {features['file_size']:.1f} MB")
            print(f"   🔐 Permissions: {features['total_permissions']} total, {features['suspicious_permissions']} suspicious")
            print(f"   📜 Certificates: {features['certificate_count']}, Valid: {bool(features['has_valid_certificates'])}")
            print(f"   🔧 API Calls: {features['total_methods']} total, {features['suspicious_apis']} suspicious")

            # Recommendation
            print(f"\n💡 RECOMMENDATION:")
            if is_legitimate:
                if confidence > 0.5:
                    print("   ✅ This APK appears to be a legitimate banking application.")
                else:
                    print("   ⚠️ This APK is likely legitimate but shows some unusual patterns.")
            else:
                if confidence > 0.3:
                    print("   🚨 This APK shows suspicious patterns and should be investigated.")
                    print("   🔍 Consider additional manual analysis or quarantine.")
                else:
                    print("   ⚠️ This APK shows some anomalous behavior but may be a false positive.")

            return {
                'file_path': apk_path,
                'is_legitimate': is_legitimate,
                'anomaly_score': float(anomaly_score),
                'confidence': float(confidence),
                'risk_percentage': float(risk_percentage),
                'features': features,
                'analysis': analysis,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            print(f"❌ Testing error: {str(e)}")
            return None

    def test_banking_apk_directory(self):
        """Test all APKs in the banking directory"""
        banking_dir = "mp_police_datasets/legitimate/banking"

        if not os.path.exists(banking_dir):
            print(f"❌ Banking directory not found: {banking_dir}")
            return

        print("🏦 Testing Legitimate Banking APKs")
        print("=" * 50)

        apk_files = [f for f in os.listdir(banking_dir) if f.endswith('.apk')]

        if not apk_files:
            print("❌ No APK files found in banking directory")
            return

        results = []
        legitimate_count = 0
        suspicious_count = 0

        for i, filename in enumerate(apk_files, 1):
            apk_path = os.path.join(banking_dir, filename)
            print(f"\n[{i}/{len(apk_files)}] Testing {filename}...")

            result = self.test_single_apk(apk_path)

            if result:
                results.append(result)
                if result['is_legitimate']:
                    legitimate_count += 1
                else:
                    suspicious_count += 1

        # Summary
        print(f"\n📊 TESTING SUMMARY:")
        print("=" * 30)
        print(f"📱 Total APKs tested: {len(results)}")
        print(f"✅ Legitimate: {legitimate_count}")
        print(f"🚨 Suspicious: {suspicious_count}")
        print(f"📈 Accuracy: {(legitimate_count/len(results)*100):.1f}%" if results else "N/A")

        # Show suspicious ones
        if suspicious_count > 0:
            print(f"\n⚠️ SUSPICIOUS BANKING APKs:")
            for result in results:
                if not result['is_legitimate']:
                    filename = os.path.basename(result['file_path'])
                    print(f"   🚨 {filename} (Risk: {result['risk_percentage']:.1f}%)")

        return results

    def test_api_integration(self):
        """Test integration with Flask API"""
        print("\n🌐 Testing API Integration")
        print("=" * 40)

        try:
            import requests

            # Test if API is running
            api_url = "http://localhost:5000/api/health"

            print("🔍 Checking if API is running...")
            try:
                response = requests.get(api_url, timeout=5)
                if response.status_code == 200:
                    print("✅ API is running and accessible")

                    # Test analyze endpoint
                    print("🧪 Testing analyze endpoint...")

                    # Find a banking APK to test
                    banking_dir = "mp_police_datasets/legitimate/banking"
                    if os.path.exists(banking_dir):
                        apk_files = [f for f in os.listdir(banking_dir) if f.endswith('.apk')]
                        if apk_files:
                            test_apk = os.path.join(banking_dir, apk_files[0])

                            # Upload APK to API
                            with open(test_apk, 'rb') as f:
                                files = {'file': f}
                                response = requests.post(
                                    "http://localhost:5000/api/analyze",
                                    files=files,
                                    timeout=30
                                )

                            if response.status_code == 200:
                                result = response.json()
                                print("✅ API analysis successful")
                                print(f"   📊 Result: {result.get('prediction', 'Unknown')}")
                                print(f"   🔒 Confidence: {result.get('confidence', 'Unknown')}")
                            else:
                                print(f"❌ API analysis failed: {response.status_code}")
                        else:
                            print("⚠️ No APK files found for testing")
                    else:
                        print("⚠️ Banking directory not found for API testing")

                else:
                    print(f"❌ API not responding: {response.status_code}")

            except requests.exceptions.ConnectionError:
                print("❌ Cannot connect to API. Make sure enhanced_app.py is running:")
                print("   python enhanced_app.py")

        except ImportError:
            print("⚠️ requests library not available for API testing")

    def interactive_testing_menu(self):
        """Interactive testing menu"""
        while True:
            print("\n🧪 Banking APK Model Testing Menu")
            print("=" * 40)
            print("1. Test single APK file")
            print("2. Test all banking APKs")
            print("3. Test API integration")
            print("4. Model information")
            print("5. Exit")

            choice = input("\nSelect option (1-5): ").strip()

            if choice == '1':
                apk_path = input("Enter APK file path: ").strip()
                if os.path.exists(apk_path) and apk_path.endswith('.apk'):
                    self.test_single_apk(apk_path)
                else:
                    print("❌ Invalid APK file path")

            elif choice == '2':
                self.test_banking_apk_directory()

            elif choice == '3':
                self.test_api_integration()

            elif choice == '4':
                self.show_model_info()

            elif choice == '5':
                print("👋 Goodbye!")
                break

            else:
                print("❌ Invalid option")

    def show_model_info(self):
        """Show model information"""
        if not self.model_loaded:
            print("❌ Model not loaded")
            return

        print("\n📊 MODEL INFORMATION")
        print("=" * 30)
        print(f"🤖 Algorithm: {self.model_metadata.get('algorithm', 'Unknown')}")
        print(f"📅 Trained: {self.model_metadata.get('training_timestamp', 'Unknown')}")
        print(f"🔢 Features: {len(self.feature_columns)}")
        print(f"⚙️ Contamination: {self.model_metadata.get('contamination', 'Unknown')}")
        print(f"🌲 Estimators: {self.model_metadata.get('n_estimators', 'Unknown')}")

        print(f"\n📋 FEATURE LIST:")
        for i, feature in enumerate(self.feature_columns, 1):
            print(f"   {i:2d}. {feature}")

def main():
    """Main testing interface"""
    print("🧪 Banking APK Anomaly Detection Model Tester")
    print("=" * 60)

    tester = BankingModelTester()

    if not tester.model_loaded:
        print("\n❌ Cannot proceed without trained model.")
        print("📋 To train the model, run:")
        print("   python train_banking_model.py")
        return

    # Run interactive testing
    tester.interactive_testing_menu()

if __name__ == "__main__":
    main()
