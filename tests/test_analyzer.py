"""
Test suite for APK analyzer components
"""

import unittest
import tempfile
import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent / 'src'))

from analysis.apk_analyzer import APKAnalyzer
from ml.classifier import APKClassifier
from utils.reporter import ReportGenerator

class TestAPKAnalyzer(unittest.TestCase):
    """Test cases for APK analyzer"""
    
    def setUp(self):
        self.analyzer = APKAnalyzer()
        self.classifier = APKClassifier()
        self.reporter = ReportGenerator()
    
    def test_suspicious_permission_detection(self):
        """Test suspicious permission identification"""
        permissions = [
            'android.permission.INTERNET',
            'android.permission.SEND_SMS',
            'android.permission.READ_SMS',
            'android.permission.SYSTEM_ALERT_WINDOW'
        ]
        
        suspicious = self.analyzer._identify_suspicious_permissions(permissions)
        
        self.assertIn('android.permission.SEND_SMS', suspicious)
        self.assertIn('android.permission.READ_SMS', suspicious)
        self.assertIn('android.permission.SYSTEM_ALERT_WINDOW', suspicious)
        self.assertNotIn('android.permission.INTERNET', suspicious)
    
    def test_package_name_analysis(self):
        """Test package name suspicious detection"""
        # Test legitimate package names
        self.assertFalse(self.analyzer._is_package_name_suspicious('com.example.bankingapp'))
        self.assertFalse(self.analyzer._is_package_name_suspicious('com.mybank.mobile'))
        
        # Test suspicious package names
        self.assertTrue(self.analyzer._is_package_name_suspicious('com.android.fake'))
        self.assertTrue(self.analyzer._is_package_name_suspicious('temp.test'))
        self.assertTrue(self.analyzer._is_package_name_suspicious('a'))  # Too short
    
    def test_risk_score_calculation(self):
        """Test risk score calculation"""
        # High risk scenario
        permissions = ['android.permission.SEND_SMS', 'android.permission.READ_SMS']
        suspicious_permissions = permissions
        certificates = [{'is_self_signed': True}]
        features = {
            'has_self_signed_cert': True,
            'cert_validity_days': 10,
            'package_name_suspicious': True,
            'permission_count': 25
        }
        
        risk_score = self.analyzer._calculate_risk_score(
            permissions, suspicious_permissions, certificates, features
        )
        
        self.assertGreater(risk_score, 50)  # Should be high risk
        self.assertLessEqual(risk_score, 100)  # Should not exceed 100

class TestMLClassifier(unittest.TestCase):
    """Test cases for ML classifier"""
    
    def setUp(self):
        self.classifier = APKClassifier()
    
    def test_synthetic_data_generation(self):
        """Test synthetic training data generation"""
        data = self.classifier.generate_synthetic_training_data(100)
        
        self.assertEqual(len(data), 100)
        self.assertIn('is_fake', data.columns)
        self.assertIn('permission_count', data.columns)
        
        # Check that we have both fake and legitimate samples
        fake_count = data['is_fake'].sum()
        legitimate_count = len(data) - fake_count
        
        self.assertGreater(fake_count, 0)
        self.assertGreater(legitimate_count, 0)
    
    def test_feature_vector_preparation(self):
        """Test feature vector preparation"""
        features = {
            'permission_count': 10,
            'has_sms_permissions': True,
            'suspicious_permission_ratio': 0.3
        }
        
        vector = self.classifier._prepare_feature_vector(features)
        
        self.assertIsInstance(vector, list)
        self.assertEqual(len(vector), len(self.classifier.expected_features))
        self.assertEqual(vector[0], 10.0)  # permission_count
        self.assertEqual(vector[4], 1.0)   # has_sms_permissions (True -> 1.0)
    
    def test_rule_based_classification(self):
        """Test rule-based classification"""
        # Mock analysis result
        class MockAnalysisResult:
            def __init__(self, risk_score, suspicious_permissions):
                self.risk_score = risk_score
                self.suspicious_permissions = suspicious_permissions
                self.features = {'has_self_signed_cert': False}
        
        # High risk case
        high_risk_result = MockAnalysisResult(80, ['perm1', 'perm2'])
        prediction = self.classifier.rule_based_classify(high_risk_result)
        
        self.assertTrue(prediction['is_fake'])
        self.assertGreater(prediction['confidence'], 0.8)
        
        # Low risk case
        low_risk_result = MockAnalysisResult(10, [])
        prediction = self.classifier.rule_based_classify(low_risk_result)
        
        self.assertFalse(prediction['is_fake'])

class TestReportGenerator(unittest.TestCase):
    """Test cases for report generator"""
    
    def setUp(self):
        self.reporter = ReportGenerator()
    
    def test_risk_level_mapping(self):
        """Test risk score to risk level mapping"""
        self.assertEqual(self.reporter._get_risk_level(90), 'CRITICAL')
        self.assertEqual(self.reporter._get_risk_level(70), 'HIGH')
        self.assertEqual(self.reporter._get_risk_level(50), 'MEDIUM')
        self.assertEqual(self.reporter._get_risk_level(30), 'LOW')
        self.assertEqual(self.reporter._get_risk_level(10), 'MINIMAL')
    
    def test_report_generation(self):
        """Test basic report generation"""
        # Mock analysis result
        class MockAnalysisResult:
            def __init__(self):
                self.package_name = 'com.test.app'
                self.app_name = 'Test App'
                self.version_name = '1.0'
                self.version_code = 1
                self.permissions = ['android.permission.INTERNET']
                self.activities = ['MainActivity']
                self.services = []
                self.receivers = []
                self.certificates = []
                self.file_hashes = {'md5': 'test', 'sha1': 'test', 'sha256': 'test'}
                self.suspicious_permissions = []
                self.network_security_config = None
                self.features = {'permission_count': 1}
                self.risk_score = 20
        
        analysis_result = MockAnalysisResult()
        prediction = {'is_fake': False, 'confidence': 0.8, 'method': 'test'}
        
        report = self.reporter.generate_report(analysis_result, prediction, 'test.apk')
        
        self.assertIn('analysis_metadata', report)
        self.assertIn('apk_information', report)
        self.assertIn('classification_result', report)
        self.assertEqual(report['apk_information']['app_name'], 'Test App')
        self.assertFalse(report['classification_result']['is_fake'])

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_full_pipeline_with_synthetic_data(self):
        """Test the complete analysis pipeline"""
        classifier = APKClassifier()
        
        # Generate and train on synthetic data
        training_data = classifier.generate_synthetic_training_data(200)
        results = classifier.train_model(training_data)
        
        self.assertIn('best_model', results)
        self.assertGreater(results['cv_auc'], 0.5)  # Should be better than random
        
        # Test prediction on a sample
        test_features = {
            'permission_count': 15,
            'activity_count': 5,
            'service_count': 2,
            'receiver_count': 1,
            'has_sms_permissions': True,
            'has_phone_permissions': False,
            'has_location_permissions': True,
            'has_camera_permissions': False,
            'has_admin_permissions': False,
            'has_system_alert': True,
            'suspicious_permission_ratio': 0.6,
            'certificate_count': 1,
            'has_self_signed_cert': True,
            'cert_validity_days': 30,
            'package_name_length': 25,
            'app_name_length': 15,
            'has_banking_keywords': True,
            'package_name_suspicious': False,
            'service_to_activity_ratio': 0.4,
            'receiver_to_activity_ratio': 0.2
        }
        
        prediction = classifier.predict(test_features)
        
        self.assertIsInstance(prediction.is_fake, bool)
        self.assertGreaterEqual(prediction.confidence, 0)
        self.assertLessEqual(prediction.confidence, 1)

if __name__ == '__main__':
    # Create test runner with verbose output
    unittest.main(verbosity=2)
