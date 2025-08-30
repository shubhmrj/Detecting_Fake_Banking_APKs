"""
Real APK Testing Script for Banking Malware Detection
This script helps you test your model with real banking APKs and malware samples.
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from apk_analyzer import EnhancedAPKAnalyzer
from ml_trainer import APKMLTrainer

class RealAPKTester:
    def __init__(self):
        self.analyzer = EnhancedAPKAnalyzer()
        self.ml_trainer = APKMLTrainer()
        
        # Try to load existing models
        try:
            self.ml_trainer.load_models()
            print("✅ Loaded existing ML models")
        except:
            print("⚠️  No existing models found. Training new models...")
            # Generate synthetic data and train models
            data = self.ml_trainer.generate_synthetic_training_data(1000)
            self.ml_trainer.train_models(data)
            self.ml_trainer.save_models()
            print("✅ New models trained and saved")
    
    def analyze_apk(self, apk_path):
        """Analyze a single APK file"""
        print(f"\n🔍 Analyzing: {os.path.basename(apk_path)}")
        print("=" * 60)
        
        try:
            # Static analysis
            static_results = self.analyzer.analyze_apk(apk_path)
            
            # ML prediction
            ml_results = self.ml_trainer.predict(static_results)
            
            # Display results
            print(f"📱 Package: {static_results.get('package_name', 'Unknown')}")
            print(f"📊 File Size: {static_results.get('file_size', 0):,} bytes")
            print(f"🔐 Signed: {'Yes' if static_results.get('is_signed') else 'No'}")
            print(f"⚠️  Permissions: {static_results.get('total_permissions', 0)} total, {static_results.get('critical_permissions', 0)} critical")
            
            # ML Prediction
            prediction = "🦠 MALICIOUS" if ml_results['prediction'] == 1 else "✅ LEGITIMATE"
            confidence = ml_results['confidence']
            
            print(f"\n🤖 ML PREDICTION: {prediction}")
            print(f"🎯 Confidence: {confidence:.1%}")
            
            # Risk factors
            if ml_results['prediction'] == 1:
                print(f"\n⚠️  TOP RISK FACTORS:")
                for feature, importance in ml_results.get('feature_importance', [])[:5]:
                    print(f"   • {feature}: {importance:.3f}")
            
            # Security analysis
            security_score = static_results.get('security_analysis', {}).get('risk_score', 0)
            print(f"\n🛡️  Security Risk Score: {security_score}/100")
            
            return {
                'file': os.path.basename(apk_path),
                'prediction': ml_results['prediction'],
                'confidence': confidence,
                'security_score': security_score,
                'package_name': static_results.get('package_name', 'Unknown')
            }
            
        except Exception as e:
            print(f"❌ Error analyzing {apk_path}: {str(e)}")
            return None
    
    def batch_analyze(self, apk_directory):
        """Analyze all APK files in a directory"""
        apk_files = list(Path(apk_directory).glob("*.apk"))
        
        if not apk_files:
            print(f"❌ No APK files found in {apk_directory}")
            return
        
        print(f"🚀 Found {len(apk_files)} APK files to analyze")
        
        results = []
        for apk_file in apk_files:
            result = self.analyze_apk(str(apk_file))
            if result:
                results.append(result)
        
        # Summary
        print(f"\n📊 BATCH ANALYSIS SUMMARY")
        print("=" * 60)
        
        malicious_count = sum(1 for r in results if r['prediction'] == 1)
        legitimate_count = len(results) - malicious_count
        
        print(f"Total APKs analyzed: {len(results)}")
        print(f"🦠 Detected as malicious: {malicious_count}")
        print(f"✅ Detected as legitimate: {legitimate_count}")
        
        if results:
            avg_confidence = sum(r['confidence'] for r in results) / len(results)
            print(f"🎯 Average confidence: {avg_confidence:.1%}")
        
        return results

def main():
    print("🏦 Banking APK Malware Detection - Real APK Tester")
    print("=" * 60)
    
    tester = RealAPKTester()
    
    print("\nHow to use this tester:")
    print("1. Place your APK files in a directory")
    print("2. Run this script and provide the directory path")
    print("3. View detailed analysis results")
    
    print("\n📁 APK File Sources:")
    print("• Legitimate Banking APKs: Download from official app stores")
    print("• Malware Samples: Use VirusTotal, MalwareBazaar, or security research datasets")
    print("• Test APKs: Create simple test apps with suspicious permissions")
    
    # Interactive mode
    while True:
        print("\nOptions:")
        print("1. Analyze single APK file")
        print("2. Batch analyze directory")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            apk_path = input("Enter APK file path: ").strip()
            if os.path.exists(apk_path):
                tester.analyze_apk(apk_path)
            else:
                print("❌ File not found!")
        
        elif choice == '2':
            directory = input("Enter directory path containing APK files: ").strip()
            if os.path.exists(directory):
                tester.batch_analyze(directory)
            else:
                print("❌ Directory not found!")
        
        elif choice == '3':
            break
        
        else:
            print("❌ Invalid choice!")

if __name__ == "__main__":
    main()
