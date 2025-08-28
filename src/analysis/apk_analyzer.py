"""
APK Static Analysis Module
Extracts features from APK files including permissions, signatures, certificates, and metadata
"""

import os
import hashlib
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path

try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
except ImportError:
    print("Warning: androguard not installed. Install with: pip install androguard")

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import zipfile
import xml.etree.ElementTree as ET

@dataclass
class APKAnalysisResult:
    """Container for APK analysis results"""
    package_name: str
    app_name: str
    version_name: str
    version_code: int
    permissions: List[str]
    activities: List[str]
    services: List[str]
    receivers: List[str]
    certificates: List[Dict[str, Any]]
    file_hashes: Dict[str, str]
    suspicious_permissions: List[str]
    network_security_config: Optional[Dict[str, Any]]
    features: Dict[str, Any]
    risk_score: float

class APKAnalyzer:
    """Main APK analysis class"""
    
    # Suspicious permissions commonly found in banking malware
    SUSPICIOUS_PERMISSIONS = {
        'android.permission.SEND_SMS': 'high',
        'android.permission.READ_SMS': 'high',
        'android.permission.RECEIVE_SMS': 'high',
        'android.permission.CALL_PHONE': 'medium',
        'android.permission.READ_PHONE_STATE': 'medium',
        'android.permission.SYSTEM_ALERT_WINDOW': 'high',
        'android.permission.WRITE_EXTERNAL_STORAGE': 'low',
        'android.permission.ACCESS_FINE_LOCATION': 'medium',
        'android.permission.CAMERA': 'medium',
        'android.permission.RECORD_AUDIO': 'medium',
        'android.permission.GET_ACCOUNTS': 'high',
        'android.permission.AUTHENTICATE_ACCOUNTS': 'high',
        'android.permission.DEVICE_ADMIN': 'high',
        'android.permission.BIND_DEVICE_ADMIN': 'high'
    }
    
    # Legitimate banking app indicators
    BANKING_KEYWORDS = [
        'bank', 'banking', 'finance', 'payment', 'wallet', 'money',
        'credit', 'debit', 'account', 'transaction', 'transfer'
    ]
    
    def __init__(self):
        self.apk = None
        
    def analyze(self, apk_path: str) -> APKAnalysisResult:
        """
        Perform comprehensive APK analysis
        """
        try:
            self.apk = APK(apk_path)
            
            # Extract basic information
            package_name = self.apk.get_package()
            app_name = self.apk.get_app_name()
            version_name = self.apk.get_androidversion_name()
            version_code = self.apk.get_androidversion_code()
            
            # Extract permissions
            permissions = self.apk.get_permissions()
            
            # Extract components
            activities = self.apk.get_activities()
            services = self.apk.get_services()
            receivers = self.apk.get_receivers()
            
            # Analyze certificates
            certificates = self._analyze_certificates()
            
            # Calculate file hashes
            file_hashes = self._calculate_hashes(apk_path)
            
            # Identify suspicious permissions
            suspicious_permissions = self._identify_suspicious_permissions(permissions)
            
            # Analyze network security config
            network_config = self._analyze_network_security()
            
            # Extract features for ML
            features = self._extract_features(
                package_name, app_name, permissions, activities, 
                services, receivers, certificates
            )
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(
                permissions, suspicious_permissions, certificates, features
            )
            
            return APKAnalysisResult(
                package_name=package_name,
                app_name=app_name,
                version_name=version_name,
                version_code=version_code,
                permissions=permissions,
                activities=activities,
                services=services,
                receivers=receivers,
                certificates=certificates,
                file_hashes=file_hashes,
                suspicious_permissions=suspicious_permissions,
                network_security_config=network_config,
                features=features,
                risk_score=risk_score
            )
            
        except Exception as e:
            raise Exception(f"APK analysis failed: {str(e)}")
    
    def _analyze_certificates(self) -> List[Dict[str, Any]]:
        """Analyze APK certificates and signatures"""
        certificates = []
        
        try:
            for cert in self.apk.get_certificates():
                cert_info = {
                    'subject': str(cert.subject),
                    'issuer': str(cert.issuer),
                    'serial_number': str(cert.serial_number),
                    'not_valid_before': cert.not_valid_before.isoformat(),
                    'not_valid_after': cert.not_valid_after.isoformat(),
                    'signature_algorithm': cert.signature_algorithm_oid._name,
                    'is_self_signed': cert.subject == cert.issuer,
                    'key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else None
                }
                certificates.append(cert_info)
        except Exception as e:
            print(f"Certificate analysis error: {e}")
            
        return certificates
    
    def _calculate_hashes(self, apk_path: str) -> Dict[str, str]:
        """Calculate various hashes of the APK file"""
        hashes = {}
        
        try:
            with open(apk_path, 'rb') as f:
                content = f.read()
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
        except Exception as e:
            print(f"Hash calculation error: {e}")
            
        return hashes
    
    def _identify_suspicious_permissions(self, permissions: List[str]) -> List[str]:
        """Identify suspicious permissions"""
        suspicious = []
        for perm in permissions:
            if perm in self.SUSPICIOUS_PERMISSIONS:
                suspicious.append(perm)
        return suspicious
    
    def _analyze_network_security(self) -> Optional[Dict[str, Any]]:
        """Analyze network security configuration"""
        try:
            # Look for network security config file
            network_config = self.apk.get_file("res/xml/network_security_config.xml")
            if network_config:
                # Parse XML and extract security settings
                root = ET.fromstring(network_config)
                config = {
                    'clear_traffic_permitted': root.get('cleartextTrafficPermitted', 'true'),
                    'trust_anchors': [],
                    'domain_configs': []
                }
                return config
        except Exception as e:
            print(f"Network security analysis error: {e}")
        
        return None
    
    def _extract_features(self, package_name: str, app_name: str, permissions: List[str],
                         activities: List[str], services: List[str], receivers: List[str],
                         certificates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract features for machine learning"""
        
        features = {
            # Basic features
            'permission_count': len(permissions),
            'activity_count': len(activities),
            'service_count': len(services),
            'receiver_count': len(receivers),
            
            # Permission-based features
            'has_sms_permissions': any('SMS' in p for p in permissions),
            'has_phone_permissions': any('PHONE' in p for p in permissions),
            'has_location_permissions': any('LOCATION' in p for p in permissions),
            'has_camera_permissions': any('CAMERA' in p for p in permissions),
            'has_admin_permissions': any('ADMIN' in p for p in permissions),
            'has_system_alert': 'android.permission.SYSTEM_ALERT_WINDOW' in permissions,
            
            # Suspicious permission ratio
            'suspicious_permission_ratio': len(self._identify_suspicious_permissions(permissions)) / max(len(permissions), 1),
            
            # Certificate features
            'certificate_count': len(certificates),
            'has_self_signed_cert': any(cert.get('is_self_signed', False) for cert in certificates),
            'cert_validity_days': self._calculate_cert_validity(certificates),
            
            # Name-based features
            'package_name_length': len(package_name),
            'app_name_length': len(app_name),
            'has_banking_keywords': any(keyword in app_name.lower() or keyword in package_name.lower() 
                                      for keyword in self.BANKING_KEYWORDS),
            'package_name_suspicious': self._is_package_name_suspicious(package_name),
            
            # Component ratios
            'service_to_activity_ratio': len(services) / max(len(activities), 1),
            'receiver_to_activity_ratio': len(receivers) / max(len(activities), 1),
        }
        
        return features
    
    def _calculate_cert_validity(self, certificates: List[Dict[str, Any]]) -> int:
        """Calculate average certificate validity period in days"""
        if not certificates:
            return 0
        
        total_days = 0
        for cert in certificates:
            try:
                from datetime import datetime
                start = datetime.fromisoformat(cert['not_valid_before'].replace('Z', '+00:00'))
                end = datetime.fromisoformat(cert['not_valid_after'].replace('Z', '+00:00'))
                days = (end - start).days
                total_days += days
            except:
                continue
        
        return total_days // max(len(certificates), 1)
    
    def _is_package_name_suspicious(self, package_name: str) -> bool:
        """Check if package name looks suspicious"""
        suspicious_patterns = [
            'com.android.', 'android.', 'system.', 'google.', 'samsung.',
            'temp.', 'test.', 'fake.', 'malware.'
        ]
        
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if package_name.startswith(pattern) and not self._is_legitimate_system_app(package_name):
                return True
        
        # Check for random-looking package names
        parts = package_name.split('.')
        if len(parts) < 2:
            return True
        
        # Check for very short or very long package names
        if len(package_name) < 10 or len(package_name) > 100:
            return True
        
        return False
    
    def _is_legitimate_system_app(self, package_name: str) -> bool:
        """Check if this is a legitimate system app"""
        legitimate_prefixes = [
            'com.android.chrome', 'com.android.vending', 'com.google.android',
            'com.samsung.android', 'com.android.settings'
        ]
        
        return any(package_name.startswith(prefix) for prefix in legitimate_prefixes)
    
    def _calculate_risk_score(self, permissions: List[str], suspicious_permissions: List[str],
                            certificates: List[Dict[str, Any]], features: Dict[str, Any]) -> float:
        """Calculate overall risk score (0-100)"""
        risk_score = 0.0
        
        # Permission-based risk
        if suspicious_permissions:
            risk_score += min(len(suspicious_permissions) * 10, 40)
        
        # Certificate-based risk
        if features.get('has_self_signed_cert', False):
            risk_score += 20
        
        if features.get('cert_validity_days', 0) < 30:
            risk_score += 15
        
        # Package name risk
        if features.get('package_name_suspicious', False):
            risk_score += 15
        
        # Excessive permissions
        if features.get('permission_count', 0) > 20:
            risk_score += 10
        
        return min(risk_score, 100.0)
