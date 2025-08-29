"""
Enhanced APK Analysis Module
Advanced static and dynamic analysis for malicious behavior detection
"""

import os
import re
import json
import zipfile
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
import xml.etree.ElementTree as ET

try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
    from androguard.misc import AnalyzeAPK
except ImportError:
    print("Warning: androguard not installed")

class EnhancedAPKAnalyzer:
    """Enhanced APK analyzer with advanced malicious behavior detection"""
    
    def __init__(self):
        # Banking-specific malicious patterns
        self.malicious_patterns = {
            'phishing_keywords': [
                'login', 'signin', 'password', 'pin', 'otp', 'verify', 'secure',
                'account', 'balance', 'transfer', 'payment', 'card', 'cvv'
            ],
            'suspicious_urls': [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
                'ngrok.io', 'serveo.net', 'localtunnel.me'
            ],
            'malicious_apis': [
                'SmsManager.sendTextMessage',
                'TelephonyManager.getDeviceId',
                'TelephonyManager.getSubscriberId',
                'ContactsContract.CommonDataKinds.Phone',
                'KeyguardManager.createConfirmDeviceCredentialIntent',
                'DevicePolicyManager.lockNow'
            ],
            'crypto_patterns': [
                'AES/CBC/PKCS5Padding',
                'RSA/ECB/PKCS1Padding',
                'javax.crypto.Cipher',
                'java.security.MessageDigest'
            ]
        }
        
        # Known legitimate banking app signatures
        self.legitimate_signatures = {
            'chase': ['CN=JPMorgan Chase'],
            'bofa': ['CN=Bank of America'],
            'wells_fargo': ['CN=Wells Fargo'],
            'citi': ['CN=Citibank']
        }
    
    def analyze_code_patterns(self, apk_path: str) -> Dict[str, Any]:
        """Analyze code for malicious patterns"""
        try:
            apk, dalvik_files, analysis = AnalyzeAPK(apk_path)
            
            results = {
                'suspicious_strings': [],
                'malicious_api_calls': [],
                'obfuscation_detected': False,
                'crypto_usage': [],
                'network_operations': [],
                'reflection_usage': False,
                'dynamic_loading': False
            }
            
            # Analyze DEX files
            for dex in dalvik_files:
                # Check for suspicious strings
                strings = dex.get_strings()
                for string_analysis in strings:
                    string_value = string_analysis.get_value()
                    if self._is_suspicious_string(string_value):
                        results['suspicious_strings'].append(string_value)
                
                # Analyze methods for malicious API calls
                for class_analysis in analysis.get_classes():
                    for method in class_analysis.get_methods():
                        method_analysis = analysis.get_method(method)
                        if method_analysis:
                            # Check API calls
                            for call in method_analysis.get_xref_to():
                                api_call = str(call[1])
                                if self._is_malicious_api(api_call):
                                    results['malicious_api_calls'].append(api_call)
                
                # Check for obfuscation
                if self._detect_obfuscation(dex):
                    results['obfuscation_detected'] = True
                
                # Check for reflection usage
                if self._detect_reflection(strings):
                    results['reflection_usage'] = True
                
                # Check for dynamic loading
                if self._detect_dynamic_loading(strings):
                    results['dynamic_loading'] = True
            
            return results
            
        except Exception as e:
            print(f"Code analysis error: {e}")
            return {}
    
    def analyze_manifest_security(self, apk_path: str) -> Dict[str, Any]:
        """Enhanced manifest analysis for security issues"""
        try:
            apk = APK(apk_path)
            manifest_xml = apk.get_android_manifest_xml()
            
            security_issues = {
                'exported_components': [],
                'dangerous_permissions': [],
                'custom_permissions': [],
                'intent_filters': [],
                'backup_allowed': False,
                'debug_enabled': False,
                'allow_clear_text': False,
                'min_sdk_version': None,
                'target_sdk_version': None
            }
            
            # Parse manifest
            root = ET.fromstring(apk.get_android_manifest_axml().get_xml())
            
            # Check application attributes
            app_element = root.find('application')
            if app_element is not None:
                security_issues['backup_allowed'] = app_element.get(
                    '{http://schemas.android.com/apk/res/android}allowBackup', 'false') == 'true'
                security_issues['debug_enabled'] = app_element.get(
                    '{http://schemas.android.com/apk/res/android}debuggable', 'false') == 'true'
            
            # Check SDK versions
            uses_sdk = root.find('uses-sdk')
            if uses_sdk is not None:
                security_issues['min_sdk_version'] = uses_sdk.get(
                    '{http://schemas.android.com/apk/res/android}minSdkVersion')
                security_issues['target_sdk_version'] = uses_sdk.get(
                    '{http://schemas.android.com/apk/res/android}targetSdkVersion')
            
            # Check permissions
            for perm in root.findall('uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if self._is_dangerous_permission(perm_name):
                    security_issues['dangerous_permissions'].append(perm_name)
            
            # Check exported components
            for component_type in ['activity', 'service', 'receiver', 'provider']:
                for component in root.findall(f'application/{component_type}'):
                    exported = component.get('{http://schemas.android.com/apk/res/android}exported')
                    if exported == 'true':
                        comp_name = component.get('{http://schemas.android.com/apk/res/android}name')
                        security_issues['exported_components'].append({
                            'type': component_type,
                            'name': comp_name
                        })
            
            return security_issues
            
        except Exception as e:
            print(f"Manifest security analysis error: {e}")
            return {}
    
    def analyze_resources(self, apk_path: str) -> Dict[str, Any]:
        """Analyze APK resources for suspicious content"""
        try:
            resource_analysis = {
                'suspicious_images': [],
                'suspicious_layouts': [],
                'hardcoded_urls': [],
                'suspicious_strings': [],
                'icon_similarity': None
            }
            
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Analyze string resources
                try:
                    strings_xml = apk_zip.read('res/values/strings.xml')
                    root = ET.fromstring(strings_xml)
                    
                    for string_elem in root.findall('string'):
                        string_value = string_elem.text
                        if string_value and self._is_suspicious_string(string_value):
                            resource_analysis['suspicious_strings'].append({
                                'name': string_elem.get('name'),
                                'value': string_value
                            })
                except:
                    pass
                
                # Check for suspicious layouts
                for file_info in apk_zip.filelist:
                    if file_info.filename.startswith('res/layout/'):
                        if self._is_suspicious_layout(file_info.filename):
                            resource_analysis['suspicious_layouts'].append(file_info.filename)
            
            return resource_analysis
            
        except Exception as e:
            print(f"Resource analysis error: {e}")
            return {}
    
    def detect_banking_app_mimicry(self, apk_path: str) -> Dict[str, Any]:
        """Detect if APK is mimicking legitimate banking apps"""
        try:
            apk = APK(apk_path)
            
            mimicry_analysis = {
                'package_name_similarity': [],
                'app_name_similarity': [],
                'icon_similarity': [],
                'certificate_mismatch': False,
                'suspicious_branding': []
            }
            
            package_name = apk.get_package()
            app_name = apk.get_app_name()
            
            # Check package name similarity to known banks
            known_banking_packages = [
                'com.chase.sig.android',
                'com.bankofamerica.digitalwallet',
                'com.wellsfargo.mobile.android',
                'com.usaa.mobile.android.usaa',
                'com.citi.citimobile'
            ]
            
            for legit_package in known_banking_packages:
                similarity = self._calculate_string_similarity(package_name, legit_package)
                if similarity > 0.7:  # High similarity threshold
                    mimicry_analysis['package_name_similarity'].append({
                        'legitimate_package': legit_package,
                        'similarity_score': similarity
                    })
            
            # Check app name similarity
            banking_names = ['Chase', 'Bank of America', 'Wells Fargo', 'Citi', 'USAA']
            for bank_name in banking_names:
                if bank_name.lower() in app_name.lower():
                    mimicry_analysis['app_name_similarity'].append(bank_name)
            
            # Check certificate legitimacy
            certificates = apk.get_certificates()
            for cert in certificates:
                cert_subject = str(cert.subject)
                if not self._is_legitimate_banking_cert(cert_subject):
                    mimicry_analysis['certificate_mismatch'] = True
            
            return mimicry_analysis
            
        except Exception as e:
            print(f"Mimicry detection error: {e}")
            return {}
    
    def _is_suspicious_string(self, string_value: str) -> bool:
        """Check if string contains suspicious patterns"""
        if not string_value or len(string_value) < 3:
            return False
        
        string_lower = string_value.lower()
        
        # Check for phishing keywords
        for keyword in self.malicious_patterns['phishing_keywords']:
            if keyword in string_lower:
                return True
        
        # Check for suspicious URLs
        for url_pattern in self.malicious_patterns['suspicious_urls']:
            if url_pattern in string_lower:
                return True
        
        # Check for hardcoded credentials patterns
        if re.search(r'password\s*=\s*["\']', string_lower):
            return True
        
        if re.search(r'api[_-]?key\s*[=:]\s*["\']', string_lower):
            return True
        
        return False
    
    def _is_malicious_api(self, api_call: str) -> bool:
        """Check if API call is potentially malicious"""
        for malicious_api in self.malicious_patterns['malicious_apis']:
            if malicious_api in api_call:
                return True
        return False
    
    def _detect_obfuscation(self, dex) -> bool:
        """Detect code obfuscation patterns"""
        try:
            # Check for short/random class names
            classes = dex.get_classes()
            suspicious_names = 0
            total_classes = len(classes)
            
            for class_def in classes:
                class_name = class_def.get_name()
                # Skip Android framework classes
                if class_name.startswith('Landroid/') or class_name.startswith('Ljava/'):
                    continue
                
                # Check for obfuscated names (single letters, random patterns)
                if self._is_obfuscated_name(class_name):
                    suspicious_names += 1
            
            # If more than 30% of classes have suspicious names, likely obfuscated
            return (suspicious_names / max(total_classes, 1)) > 0.3
            
        except Exception:
            return False
    
    def _is_obfuscated_name(self, name: str) -> bool:
        """Check if class/method name appears obfuscated"""
        # Remove package prefix
        simple_name = name.split('/')[-1].rstrip(';')
        
        # Single character names
        if len(simple_name) == 1:
            return True
        
        # Very short names with no vowels
        if len(simple_name) <= 3 and not re.search(r'[aeiouAEIOU]', simple_name):
            return True
        
        # Random-looking patterns
        if re.match(r'^[a-z]{1,3}$', simple_name):
            return True
        
        return False
    
    def _detect_reflection(self, strings) -> bool:
        """Detect reflection usage"""
        reflection_patterns = [
            'java.lang.reflect',
            'getDeclaredMethod',
            'getMethod',
            'invoke',
            'Class.forName'
        ]
        
        for string_analysis in strings:
            string_value = string_analysis.get_value()
            for pattern in reflection_patterns:
                if pattern in string_value:
                    return True
        return False
    
    def _detect_dynamic_loading(self, strings) -> bool:
        """Detect dynamic code loading"""
        loading_patterns = [
            'DexClassLoader',
            'PathClassLoader',
            'loadClass',
            'dalvik.system'
        ]
        
        for string_analysis in strings:
            string_value = string_analysis.get_value()
            for pattern in loading_patterns:
                if pattern in string_value:
                    return True
        return False
    
    def _is_dangerous_permission(self, permission: str) -> bool:
        """Check if permission is dangerous"""
        dangerous_permissions = [
            'android.permission.SEND_SMS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.CALL_PHONE',
            'android.permission.READ_PHONE_STATE',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.DEVICE_ADMIN',
            'android.permission.BIND_DEVICE_ADMIN',
            'android.permission.GET_ACCOUNTS',
            'android.permission.AUTHENTICATE_ACCOUNTS'
        ]
        return permission in dangerous_permissions
    
    def _is_suspicious_layout(self, layout_name: str) -> bool:
        """Check if layout name suggests phishing"""
        suspicious_layouts = [
            'login', 'signin', 'password', 'pin', 'otp',
            'card', 'payment', 'transfer', 'balance'
        ]
        layout_lower = layout_name.lower()
        return any(sus in layout_lower for sus in suspicious_layouts)
    
    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings using Levenshtein distance"""
        if len(str1) == 0:
            return len(str2)
        if len(str2) == 0:
            return len(str1)
        
        # Create matrix
        matrix = [[0] * (len(str2) + 1) for _ in range(len(str1) + 1)]
        
        # Initialize first row and column
        for i in range(len(str1) + 1):
            matrix[i][0] = i
        for j in range(len(str2) + 1):
            matrix[0][j] = j
        
        # Fill matrix
        for i in range(1, len(str1) + 1):
            for j in range(1, len(str2) + 1):
                if str1[i-1] == str2[j-1]:
                    cost = 0
                else:
                    cost = 1
                
                matrix[i][j] = min(
                    matrix[i-1][j] + 1,      # deletion
                    matrix[i][j-1] + 1,      # insertion
                    matrix[i-1][j-1] + cost  # substitution
                )
        
        # Convert distance to similarity
        max_len = max(len(str1), len(str2))
        distance = matrix[len(str1)][len(str2)]
        return 1 - (distance / max_len)
    
    def _is_legitimate_banking_cert(self, cert_subject: str) -> bool:
        """Check if certificate appears to be from legitimate banking institution"""
        for bank, signatures in self.legitimate_signatures.items():
            for sig_pattern in signatures:
                if sig_pattern in cert_subject:
                    return True
        return False
