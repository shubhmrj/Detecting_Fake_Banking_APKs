#!/usr/bin/env python3
"""
Demo script for the Fake Banking APK Detection System
Demonstrates the system capabilities with sample data
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent / 'src'))

from ml.classifier import APKClassifier
from utils.reporter import ReportGenerator
import pandas as pd

def main():
    print("=" * 60)
    print("FAKE BANKING APK DETECTION SYSTEM - DEMO")
    print("=" * 60)
    
    # Initialize components
    classifier = APKClassifier()
    reporter = ReportGenerator()
    
    print("\n1. Generating synthetic training data...")
    training_data = classifier.generate_synthetic_training_data(1000)
    print(f"Generated {len(training_data)} samples")
    print(f"Legitimate apps: {len(training_data[training_data['is_fake'] == 0])}")
    print(f"Fake apps: {len(training_data[training_data['is_fake'] == 1])}")
    
    print("\n2. Training machine learning model...")
    results = classifier.train_model(training_data)
    print(f"Best model: {results['best_model']}")
    print(f"Cross-validation AUC: {results['cv_auc']:.4f}")
    print(f"Test AUC: {results['test_auc']:.4f}")
    
    print("\n3. Testing with sample APK features...")
    
    # Test case 1: Suspicious fake banking app
    print("\n--- Test Case 1: Suspicious App ---")
    fake_app_features = {
        'permission_count': 28,
        'activity_count': 4,
        'service_count': 8,
        'receiver_count': 6,
        'has_sms_permissions': True,
        'has_phone_permissions': True,
        'has_location_permissions': True,
        'has_camera_permissions': True,
        'has_admin_permissions': True,
        'has_system_alert': True,
        'suspicious_permission_ratio': 0.8,
        'certificate_count': 1,
        'has_self_signed_cert': True,
        'cert_validity_days': 15,
        'package_name_length': 45,
        'app_name_length': 20,
        'has_banking_keywords': True,
        'package_name_suspicious': True,
        'service_to_activity_ratio': 2.0,
        'receiver_to_activity_ratio': 1.5
    }
    
    prediction1 = classifier.predict(fake_app_features)
    print(f"Classification: {'FAKE' if prediction1.is_fake else 'LEGITIMATE'}")
    print(f"Confidence: {prediction1.confidence:.3f}")
    print(f"Fake probability: {prediction1.probability_fake:.3f}")
    
    # Test case 2: Legitimate banking app
    print("\n--- Test Case 2: Legitimate App ---")
    legit_app_features = {
        'permission_count': 12,
        'activity_count': 8,
        'service_count': 3,
        'receiver_count': 2,
        'has_sms_permissions': False,
        'has_phone_permissions': False,
        'has_location_permissions': True,
        'has_camera_permissions': True,
        'has_admin_permissions': False,
        'has_system_alert': False,
        'suspicious_permission_ratio': 0.1,
        'certificate_count': 1,
        'has_self_signed_cert': False,
        'cert_validity_days': 1095,
        'package_name_length': 35,
        'app_name_length': 25,
        'has_banking_keywords': True,
        'package_name_suspicious': False,
        'service_to_activity_ratio': 0.375,
        'receiver_to_activity_ratio': 0.25
    }
    
    prediction2 = classifier.predict(legit_app_features)
    print(f"Classification: {'FAKE' if prediction2.is_fake else 'LEGITIMATE'}")
    print(f"Confidence: {prediction2.confidence:.3f}")
    print(f"Fake probability: {prediction2.probability_fake:.3f}")
    
    print("\n4. Feature importance analysis...")
    feature_importance = prediction1.feature_importance
    print("Top 5 most important features:")
    for i, (feature, importance) in enumerate(list(feature_importance.items())[:5]):
        print(f"{i+1}. {feature}: {importance:.4f}")
    
    print("\n5. Saving demo model...")
    os.makedirs('models', exist_ok=True)
    classifier.save_model('models/demo_banking_apk_classifier.pkl')
    print("Model saved to models/demo_banking_apk_classifier.pkl")
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Run the web interface: python src/web/app.py")
    print("2. Upload APK files for analysis")
    print("3. View detailed reports and recommendations")
    print("\nFor hackathon presentation:")
    print("- Show the web interface demo")
    print("- Explain the ML model performance")
    print("- Demonstrate real-time APK analysis")

if __name__ == "__main__":
    main()
