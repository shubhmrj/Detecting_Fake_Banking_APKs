"""
Enhanced APK Analyzer using Androguard
Phase 1: Comprehensive APK Metadata Extraction
"""

from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis
from androguard.misc import AnalyzeAPK
import hashlib
import json
import re
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import base64

class EnhancedAPKAnalyzer:
    """Enhanced APK analyzer with real metadata extraction"""
    
    def __init__(self):
        self.suspicious_permissions = {
            'android.permission.SEND_SMS': {'severity': 'high', 'reason': 'Can send SMS messages'},
            'android.permission.READ_SMS': {'severity': 'high', 'reason': 'Can read SMS messages'},
            'android.permission.RECEIVE_SMS': {'severity': 'high', 'reason': 'Can receive SMS messages'},
            'android.permission.CALL_PHONE': {'severity': 'medium', 'reason': 'Can make phone calls'},
            'android.permission.READ_PHONE_STATE': {'severity': 'medium', 'reason': 'Can read phone state'},
            'android.permission.SYSTEM_ALERT_WINDOW': {'severity': 'high', 'reason': 'Can display over other apps'},
            'android.permission.DEVICE_ADMIN': {'severity': 'critical', 'reason': 'Device administrator privileges'},
            'android.permission.GET_ACCOUNTS': {'severity': 'high', 'reason': 'Can access account information'},
            'android.permission.ACCESS_FINE_LOCATION': {'severity': 'medium', 'reason': 'Can access precise location'},
            'android.permission.CAMERA': {'severity': 'medium', 'reason': 'Can access camera'},
            'android.permission.RECORD_AUDIO': {'severity': 'medium', 'reason': 'Can record audio'},
            'android.permission.WRITE_EXTERNAL_STORAGE': {'severity': 'low', 'reason': 'Can write to external storage'},
            'android.permission.READ_CONTACTS': {'severity': 'medium', 'reason': 'Can read contacts'},
            'android.permission.WRITE_CONTACTS': {'severity': 'medium', 'reason': 'Can modify contacts'},
            'android.permission.INSTALL_PACKAGES': {'severity': 'critical', 'reason': 'Can install other apps'},
            'android.permission.DELETE_PACKAGES': {'severity': 'critical', 'reason': 'Can uninstall apps'}
        }
        
        self.banking_keywords = [
            'bank', 'banking', 'finance', 'financial', 'payment', 'wallet', 'money',
            'credit', 'debit', 'account', 'transaction', 'transfer', 'loan', 'mortgage',
            'invest', 'trading', 'crypto', 'currency', 'paypal', 'venmo', 'zelle'
        ]
        
        self.suspicious_apis = [
            'getDeviceId', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number',
            'sendTextMessage', 'Runtime.exec', 'ProcessBuilder', 'DexClassLoader',
            'PathClassLoader', 'URLClassLoader', 'System.loadLibrary', 'TelephonyManager',
            'SmsManager', 'LocationManager', 'AudioRecord', 'MediaRecorder'
        ]
    
    def analyze_apk(self, apk_path):
        """Comprehensive APK analysis using Androguard"""
        try:
            # Parse APK using Androguard
            apk_obj, dalvik_vm_format, analysis_obj = AnalyzeAPK(apk_path)
            
            # Extract basic metadata
            metadata = self._extract_metadata(apk_obj)
            
            # Extract permissions
            permissions = self._extract_permissions(apk_obj)
            
            # Extract components
            components = self._extract_components(apk_obj)
            
            # Extract certificates
            certificates = self._extract_certificates(apk_obj)
            
            # Extract API calls
            api_calls = self._extract_api_calls(dalvik_vm_format, analysis_obj)
            
            # Extract URLs and network endpoints
            urls = self._extract_urls(dalvik_vm_format)
            
            # Phase 2: Enhanced Static Analysis
            string_analysis = self._analyze_strings(dalvik_vm_format)
            code_analysis = self._analyze_code_patterns(dalvik_vm_format, analysis_obj)
            native_analysis = self._analyze_native_libraries(apk_obj)
            obfuscation_analysis = self._detect_obfuscation(dalvik_vm_format, analysis_obj)
            
            # Calculate file hash
            file_hash = self._calculate_hash(apk_path)
            
            # Perform security analysis
            security_analysis = self._perform_security_analysis(
                metadata, permissions, certificates, api_calls, urls, 
                string_analysis, code_analysis, obfuscation_analysis
            )
            
            # Build comprehensive result
            result = {
                'file_hash': file_hash,
                'metadata': metadata,
                'permissions': permissions,
                'components': components,
                'certificates': certificates,
                'api_calls': api_calls,
                'urls': urls,
                'string_analysis': string_analysis,
                'code_analysis': code_analysis,
                'native_analysis': native_analysis,
                'obfuscation_analysis': obfuscation_analysis,
                'security_analysis': security_analysis,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            return {'error': f'APK analysis failed: {str(e)}'}
    
    def _extract_metadata(self, apk_obj):
        """Extract basic APK metadata"""
        try:
            return {
                'package_name': apk_obj.get_package(),
                'app_name': apk_obj.get_app_name(),
                'version_name': apk_obj.get_androidversion_name(),
                'version_code': apk_obj.get_androidversion_code(),
                'min_sdk': apk_obj.get_min_sdk_version(),
                'target_sdk': apk_obj.get_target_sdk_version(),
                'compile_sdk': apk_obj.get_compile_sdk_version(),
                'main_activity': apk_obj.get_main_activity(),
                'file_size': len(apk_obj.get_raw()),
                'is_signed': len(apk_obj.get_certificates()) > 0,
                'is_debuggable': apk_obj.is_debuggable(),
                'uses_native_code': len(apk_obj.get_libraries()) > 0,
                'libraries': apk_obj.get_libraries()
            }
        except Exception as e:
            return {'error': f'Metadata extraction failed: {str(e)}'}
    
    def _extract_permissions(self, apk_obj):
        """Extract and analyze permissions"""
        try:
            permissions = apk_obj.get_permissions()
            
            permission_analysis = {
                'total_count': len(permissions),
                'permissions': [],
                'suspicious_permissions': [],
                'permission_categories': {
                    'critical': [],
                    'high': [],
                    'medium': [],
                    'low': []
                }
            }
            
            for perm in permissions:
                perm_info = {
                    'name': perm,
                    'is_suspicious': perm in self.suspicious_permissions
                }
                
                if perm in self.suspicious_permissions:
                    perm_data = self.suspicious_permissions[perm]
                    perm_info.update({
                        'severity': perm_data['severity'],
                        'reason': perm_data['reason']
                    })
                    permission_analysis['suspicious_permissions'].append(perm_info)
                    permission_analysis['permission_categories'][perm_data['severity']].append(perm)
                
                permission_analysis['permissions'].append(perm_info)
            
            return permission_analysis
            
        except Exception as e:
            return {'error': f'Permission extraction failed: {str(e)}'}
    
    def _extract_components(self, apk_obj):
        """Extract APK components (activities, services, receivers)"""
        try:
            return {
                'activities': apk_obj.get_activities(),
                'services': apk_obj.get_services(),
                'receivers': apk_obj.get_receivers(),
                'providers': apk_obj.get_providers(),
                'exported_activities': [act for act in apk_obj.get_activities() 
                                      if apk_obj.is_activity_exported(act)],
                'exported_services': [svc for svc in apk_obj.get_services() 
                                    if apk_obj.is_service_exported(svc)],
                'exported_receivers': [rcv for rcv in apk_obj.get_receivers() 
                                     if apk_obj.is_receiver_exported(rcv)]
            }
        except Exception as e:
            return {'error': f'Component extraction failed: {str(e)}'}
    
    def _extract_certificates(self, apk_obj):
        """Extract and analyze certificates"""
        try:
            certificates = []
            
            for cert_der in apk_obj.get_certificates_der_v2() or apk_obj.get_certificates_der_v3():
                try:
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    cert_info = {
                        'subject': str(cert.subject),
                        'issuer': str(cert.issuer),
                        'serial_number': str(cert.serial_number),
                        'version': cert.version.name,
                        'not_valid_before': cert.not_valid_before.isoformat(),
                        'not_valid_after': cert.not_valid_after.isoformat(),
                        'is_expired': cert.not_valid_after < datetime.now(),
                        'is_self_signed': cert.subject == cert.issuer,
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'public_key_algorithm': cert.public_key().__class__.__name__,
                        'fingerprint_sha256': cert.fingerprint(hashlib.sha256()).hex()
                    }
                    
                    certificates.append(cert_info)
                    
                except Exception as cert_error:
                    certificates.append({'error': f'Certificate parsing failed: {str(cert_error)}'})
            
            return {
                'certificate_count': len(certificates),
                'certificates': certificates,
                'has_valid_certificates': any(not cert.get('is_expired', True) for cert in certificates if 'error' not in cert),
                'has_self_signed': any(cert.get('is_self_signed', False) for cert in certificates if 'error' not in cert)
            }
            
        except Exception as e:
            return {'error': f'Certificate extraction failed: {str(e)}'}
    
    def _extract_api_calls(self, dalvik_vm_format, analysis_obj):
        """Extract API calls from DEX bytecode"""
        try:
            api_calls = {
                'total_methods': 0,
                'suspicious_apis': [],
                'crypto_apis': [],
                'network_apis': [],
                'telephony_apis': [],
                'reflection_apis': []
            }
            
            if not dalvik_vm_format or not analysis_obj:
                return api_calls
            
            # Analyze all methods
            for method in analysis_obj.get_methods():
                api_calls['total_methods'] += 1
                
                # Get method calls
                for _, call, _ in method.get_xref_to():
                    call_name = call.get_method().get_name()
                    class_name = call.get_method().get_class_name()
                    full_call = f"{class_name}.{call_name}"
                    
                    # Check for suspicious APIs
                    if any(sus_api in full_call for sus_api in self.suspicious_apis):
                        api_calls['suspicious_apis'].append(full_call)
                    
                    # Categorize API calls
                    if any(crypto in full_call.lower() for crypto in ['cipher', 'encrypt', 'decrypt', 'hash', 'digest']):
                        api_calls['crypto_apis'].append(full_call)
                    
                    if any(net in full_call.lower() for net in ['http', 'url', 'socket', 'network']):
                        api_calls['network_apis'].append(full_call)
                    
                    if 'telephony' in full_call.lower() or 'sms' in full_call.lower():
                        api_calls['telephony_apis'].append(full_call)
                    
                    if any(refl in full_call.lower() for refl in ['reflect', 'invoke', 'getmethod', 'getclass']):
                        api_calls['reflection_apis'].append(full_call)
            
            # Remove duplicates and limit results
            for key in ['suspicious_apis', 'crypto_apis', 'network_apis', 'telephony_apis', 'reflection_apis']:
                api_calls[key] = list(set(api_calls[key]))[:50]  # Limit to 50 entries each
            
            return api_calls
            
        except Exception as e:
            return {'error': f'API call extraction failed: {str(e)}'}
    
    def _extract_urls(self, dalvik_vm_format):
        """Extract URLs and network endpoints from APK"""
        try:
            urls = {
                'http_urls': [],
                'https_urls': [],
                'ip_addresses': [],
                'domains': [],
                'suspicious_urls': []
            }
            
            if not dalvik_vm_format:
                return urls
            
            # Regular expressions for URL extraction
            url_patterns = [
                r'https?://[^\s<>"{}|\\^`\[\]]+',
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            ]
            
            # Search through all strings in the APK
            for dex in dalvik_vm_format:
                for string in dex.get_strings():
                    string_value = string.get_value()
                    
                    for pattern in url_patterns:
                        matches = re.findall(pattern, string_value)
                        for match in matches:
                            if match.startswith('http://'):
                                urls['http_urls'].append(match)
                            elif match.startswith('https://'):
                                urls['https_urls'].append(match)
                            elif re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', match):
                                urls['ip_addresses'].append(match)
                            elif '.' in match and not match.startswith('http'):
                                urls['domains'].append(match)
                            
                            # Check for suspicious URLs
                            if any(sus in match.lower() for sus in ['bit.ly', 'tinyurl', 'ngrok', 'serveo']):
                                urls['suspicious_urls'].append(match)
            
            # Remove duplicates and clean up
            for key in urls:
                urls[key] = list(set(urls[key]))[:20]  # Limit to 20 entries each
            
            return urls
            
        except Exception as e:
            return {'error': f'URL extraction failed: {str(e)}'}
    
    def _calculate_hash(self, file_path):
        """Calculate SHA256 hash of APK file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _analyze_strings(self, dalvik_vm_format):
        """Advanced string analysis for suspicious patterns"""
        try:
            analysis = {
                'total_strings': 0,
                'suspicious_strings': [],
                'hardcoded_secrets': [],
                'banking_keywords': [],
                'malware_indicators': [],
                'encoded_strings': [],
                'string_entropy': 0
            }
            
            if not dalvik_vm_format:
                return analysis
            
            suspicious_patterns = [
                r'(?i)(password|passwd|pwd|secret|key|token|api[_-]?key)',
                r'(?i)(credit[_-]?card|ssn|social[_-]?security)',
                r'(?i)(hack|crack|exploit|malware|trojan|virus)',
                r'(?i)(root|su|busybox|superuser)',
                r'(?i)(shell|exec|system|runtime)',
                r'(?i)(phish|scam|fraud|steal|fake)'
            ]
            
            encoded_patterns = [
                r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
                r'[0-9a-fA-F]{32,}',  # Hex strings
                r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
            ]
            
            all_strings = []
            
            for dex in dalvik_vm_format:
                for string in dex.get_strings():
                    string_value = string.get_value()
                    all_strings.append(string_value)
                    analysis['total_strings'] += 1
                    
                    # Check for suspicious patterns
                    for pattern in suspicious_patterns:
                        if re.search(pattern, string_value):
                            analysis['suspicious_strings'].append(string_value[:100])
                    
                    # Check for banking keywords
                    if any(keyword in string_value.lower() for keyword in self.banking_keywords):
                        analysis['banking_keywords'].append(string_value[:100])
                    
                    # Check for encoded strings
                    for pattern in encoded_patterns:
                        if re.search(pattern, string_value):
                            analysis['encoded_strings'].append(string_value[:100])
                    
                    # Check for hardcoded secrets (simple heuristic)
                    if len(string_value) > 20 and any(char in string_value for char in '!@#$%^&*'):
                        if re.search(r'[A-Za-z0-9]{20,}', string_value):
                            analysis['hardcoded_secrets'].append(string_value[:100])
            
            # Calculate string entropy (measure of randomness/obfuscation)
            if all_strings:
                combined_strings = ' '.join(all_strings)
                analysis['string_entropy'] = self._calculate_entropy(combined_strings)
            
            # Remove duplicates and limit results
            for key in ['suspicious_strings', 'banking_keywords', 'encoded_strings', 'hardcoded_secrets']:
                analysis[key] = list(set(analysis[key]))[:20]
            
            return analysis
            
        except Exception as e:
            return {'error': f'String analysis failed: {str(e)}'}
    
    def _analyze_code_patterns(self, dalvik_vm_format, analysis_obj):
        """Analyze code patterns and control flow"""
        try:
            analysis = {
                'total_classes': 0,
                'obfuscated_classes': [],
                'dynamic_loading': [],
                'anti_analysis': [],
                'crypto_usage': [],
                'network_patterns': [],
                'reflection_usage': []
            }
            
            if not dalvik_vm_format or not analysis_obj:
                return analysis
            
            # Analyze classes and methods
            for class_analysis in analysis_obj.get_classes():
                class_name = class_analysis.get_vm_class().get_name()
                analysis['total_classes'] += 1
                
                # Check for obfuscated class names
                if self._is_obfuscated_name(class_name):
                    analysis['obfuscated_classes'].append(class_name)
                
                # Analyze methods in class
                for method in class_analysis.get_methods():
                    method_name = method.get_method().get_name()
                    
                    # Check for dynamic loading patterns
                    if any(pattern in method_name.lower() for pattern in ['loadclass', 'defineclass', 'dexclassloader']):
                        analysis['dynamic_loading'].append(f"{class_name}.{method_name}")
                    
                    # Check for anti-analysis techniques
                    if any(pattern in method_name.lower() for pattern in ['debug', 'trace', 'monitor', 'detect']):
                        analysis['anti_analysis'].append(f"{class_name}.{method_name}")
                    
                    # Check for crypto usage
                    if any(pattern in method_name.lower() for pattern in ['encrypt', 'decrypt', 'cipher', 'hash']):
                        analysis['crypto_usage'].append(f"{class_name}.{method_name}")
                    
                    # Check for network patterns
                    if any(pattern in method_name.lower() for pattern in ['http', 'socket', 'url', 'connect']):
                        analysis['network_patterns'].append(f"{class_name}.{method_name}")
                    
                    # Check for reflection usage
                    if any(pattern in method_name.lower() for pattern in ['invoke', 'getmethod', 'getfield', 'reflect']):
                        analysis['reflection_usage'].append(f"{class_name}.{method_name}")
            
            # Limit results
            for key in ['obfuscated_classes', 'dynamic_loading', 'anti_analysis', 'crypto_usage', 'network_patterns', 'reflection_usage']:
                analysis[key] = list(set(analysis[key]))[:20]
            
            return analysis
            
        except Exception as e:
            return {'error': f'Code pattern analysis failed: {str(e)}'}
    
    def _analyze_native_libraries(self, apk_obj):
        """Analyze native libraries if present"""
        try:
            analysis = {
                'has_native_code': False,
                'native_libraries': [],
                'architectures': [],
                'suspicious_libraries': [],
                'library_analysis': {}
            }
            
            libraries = apk_obj.get_libraries()
            if libraries:
                analysis['has_native_code'] = True
                analysis['native_libraries'] = libraries
                
                # Extract architectures from library paths
                for lib in libraries:
                    if 'arm64-v8a' in lib:
                        analysis['architectures'].append('arm64-v8a')
                    elif 'armeabi-v7a' in lib:
                        analysis['architectures'].append('armeabi-v7a')
                    elif 'x86_64' in lib:
                        analysis['architectures'].append('x86_64')
                    elif 'x86' in lib:
                        analysis['architectures'].append('x86')
                
                # Check for suspicious library names
                suspicious_lib_patterns = ['hook', 'inject', 'bypass', 'root', 'hide']
                for lib in libraries:
                    if any(pattern in lib.lower() for pattern in suspicious_lib_patterns):
                        analysis['suspicious_libraries'].append(lib)
                
                analysis['architectures'] = list(set(analysis['architectures']))
            
            return analysis
            
        except Exception as e:
            return {'error': f'Native library analysis failed: {str(e)}'}
    
    def _detect_obfuscation(self, dalvik_vm_format, analysis_obj):
        """Detect code obfuscation techniques"""
        try:
            analysis = {
                'is_obfuscated': False,
                'obfuscation_score': 0,
                'obfuscation_techniques': [],
                'string_obfuscation': False,
                'control_flow_obfuscation': False,
                'name_obfuscation': False
            }
            
            if not dalvik_vm_format or not analysis_obj:
                return analysis
            
            obfuscated_names = 0
            total_names = 0
            short_method_names = 0
            
            # Analyze class and method names for obfuscation
            for class_analysis in analysis_obj.get_classes():
                class_name = class_analysis.get_vm_class().get_name()
                total_names += 1
                
                if self._is_obfuscated_name(class_name):
                    obfuscated_names += 1
                
                for method in class_analysis.get_methods():
                    method_name = method.get_method().get_name()
                    total_names += 1
                    
                    if self._is_obfuscated_name(method_name):
                        obfuscated_names += 1
                    
                    if len(method_name) <= 2 and method_name not in ['<init>', '<clinit>']:
                        short_method_names += 1
            
            # Calculate obfuscation metrics
            if total_names > 0:
                obfuscation_ratio = obfuscated_names / total_names
                short_name_ratio = short_method_names / total_names
                
                if obfuscation_ratio > 0.3:
                    analysis['name_obfuscation'] = True
                    analysis['obfuscation_techniques'].append('Name obfuscation')
                    analysis['obfuscation_score'] += 30
                
                if short_name_ratio > 0.2:
                    analysis['obfuscation_techniques'].append('Short method names')
                    analysis['obfuscation_score'] += 20
            
            # Check for string obfuscation patterns
            encrypted_strings = 0
            total_strings = 0
            
            for dex in dalvik_vm_format:
                for string in dex.get_strings():
                    string_value = string.get_value()
                    total_strings += 1
                    
                    # Check for encrypted/encoded strings
                    if (len(string_value) > 10 and 
                        (re.match(r'^[A-Za-z0-9+/]+=*$', string_value) or  # Base64-like
                         re.match(r'^[0-9a-fA-F]+$', string_value) or      # Hex-like
                         self._calculate_entropy(string_value) > 4.5)):     # High entropy
                        encrypted_strings += 1
            
            if total_strings > 0 and encrypted_strings / total_strings > 0.1:
                analysis['string_obfuscation'] = True
                analysis['obfuscation_techniques'].append('String encryption')
                analysis['obfuscation_score'] += 25
            
            # Determine if app is obfuscated
            analysis['is_obfuscated'] = analysis['obfuscation_score'] > 40
            
            return analysis
            
        except Exception as e:
            return {'error': f'Obfuscation detection failed: {str(e)}'}
    
    def _is_obfuscated_name(self, name):
        """Check if a class/method name appears obfuscated"""
        if not name or name in ['<init>', '<clinit>']:
            return False
        
        # Remove package prefixes for analysis
        simple_name = name.split('.')[-1] if '.' in name else name
        simple_name = simple_name.replace('$', '')
        
        # Check for obfuscation patterns
        if len(simple_name) <= 2:
            return True
        
        # Check for single character or very short names
        if re.match(r'^[a-zA-Z]$', simple_name):
            return True
        
        # Check for random-looking names (high consonant ratio, no vowels, etc.)
        vowels = 'aeiouAEIOU'
        consonants = 'bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ'
        
        if len(simple_name) > 2:
            vowel_count = sum(1 for c in simple_name if c in vowels)
            consonant_count = sum(1 for c in simple_name if c in consonants)
            
            if vowel_count == 0 and consonant_count > 2:
                return True
            
            if consonant_count > 0 and vowel_count / len(simple_name) < 0.1:
                return True
        
        return False
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        text_len = len(text)
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _perform_security_analysis(self, metadata, permissions, certificates, api_calls, urls, 
                                 string_analysis, code_analysis, obfuscation_analysis):
        """Perform comprehensive security analysis"""
        try:
            analysis = {
                'risk_score': 0,
                'risk_level': 'MINIMAL',
                'is_suspicious': False,
                'risk_factors': [],
                'security_issues': [],
                'recommendations': []
            }
            
            # Analyze permissions
            if permissions.get('permission_categories', {}).get('critical'):
                analysis['risk_score'] += 40
                analysis['risk_factors'].append('Critical permissions detected')
                analysis['security_issues'].append(f"Critical permissions: {', '.join(permissions['permission_categories']['critical'])}")
            
            if permissions.get('permission_categories', {}).get('high'):
                analysis['risk_score'] += 25
                analysis['risk_factors'].append('High-risk permissions detected')
            
            # Analyze certificates
            if certificates.get('has_self_signed'):
                analysis['risk_score'] += 30
                analysis['risk_factors'].append('Self-signed certificate')
                analysis['security_issues'].append('App uses self-signed certificate (not from trusted CA)')
            
            if not certificates.get('has_valid_certificates'):
                analysis['risk_score'] += 35
                analysis['risk_factors'].append('Invalid or expired certificates')
                analysis['security_issues'].append('App certificates are expired or invalid')
            
            # Analyze API calls
            if api_calls.get('suspicious_apis'):
                analysis['risk_score'] += 20
                analysis['risk_factors'].append('Suspicious API calls detected')
                analysis['security_issues'].append(f"Suspicious APIs: {', '.join(api_calls['suspicious_apis'][:5])}")
            
            if api_calls.get('reflection_apis'):
                analysis['risk_score'] += 15
                analysis['risk_factors'].append('Reflection APIs used (possible obfuscation)')
            
            # Analyze URLs
            if urls.get('suspicious_urls'):
                analysis['risk_score'] += 25
                analysis['risk_factors'].append('Suspicious URLs found')
                analysis['security_issues'].append(f"Suspicious URLs: {', '.join(urls['suspicious_urls'])}")
            
            if urls.get('http_urls'):
                analysis['risk_score'] += 10
                analysis['risk_factors'].append('Insecure HTTP connections')
                analysis['security_issues'].append('App uses insecure HTTP connections')
            
            # Phase 2: Enhanced Static Analysis
            
            # Analyze strings
            if string_analysis.get('suspicious_strings'):
                analysis['risk_score'] += 20
                analysis['risk_factors'].append('Suspicious strings detected')
                analysis['security_issues'].append(f"Suspicious strings found: {len(string_analysis['suspicious_strings'])} instances")
            
            if string_analysis.get('hardcoded_secrets'):
                analysis['risk_score'] += 30
                analysis['risk_factors'].append('Hardcoded secrets detected')
                analysis['security_issues'].append('App contains hardcoded secrets or API keys')
            
            if string_analysis.get('string_entropy', 0) > 4.0:
                analysis['risk_score'] += 15
                analysis['risk_factors'].append('High string entropy (possible obfuscation)')
            
            # Analyze code patterns
            if code_analysis.get('dynamic_loading'):
                analysis['risk_score'] += 25
                analysis['risk_factors'].append('Dynamic code loading detected')
                analysis['security_issues'].append('App uses dynamic class loading (potential security risk)')
            
            if code_analysis.get('anti_analysis'):
                analysis['risk_score'] += 30
                analysis['risk_factors'].append('Anti-analysis techniques detected')
                analysis['security_issues'].append('App contains anti-debugging/analysis code')
            
            if len(code_analysis.get('obfuscated_classes', [])) > 10:
                analysis['risk_score'] += 20
                analysis['risk_factors'].append('Many obfuscated class names')
            
            # Analyze obfuscation
            if obfuscation_analysis.get('is_obfuscated'):
                analysis['risk_score'] += 25
                analysis['risk_factors'].append('Code obfuscation detected')
                analysis['security_issues'].append(f"Obfuscation techniques: {', '.join(obfuscation_analysis.get('obfuscation_techniques', []))}")
            
            if obfuscation_analysis.get('string_obfuscation'):
                analysis['risk_score'] += 20
                analysis['risk_factors'].append('String obfuscation detected')
            
            # Analyze app metadata
            if metadata.get('is_debuggable'):
                analysis['risk_score'] += 15
                analysis['risk_factors'].append('Debug mode enabled')
                analysis['security_issues'].append('App is debuggable (security risk)')
            
            # Check if app name suggests banking but has suspicious characteristics
            app_name = metadata.get('app_name', '').lower()
            if any(keyword in app_name for keyword in self.banking_keywords):
                if analysis['risk_score'] > 30:
                    analysis['risk_score'] += 20
                    analysis['risk_factors'].append('Banking app with suspicious characteristics')
                
                # Additional banking-specific checks
                if string_analysis.get('banking_keywords') and analysis['risk_score'] > 50:
                    analysis['risk_score'] += 15
                    analysis['risk_factors'].append('Banking keywords in suspicious context')
            
            # Determine final risk level
            analysis['risk_score'] = min(analysis['risk_score'], 100)
            
            if analysis['risk_score'] >= 80:
                analysis['risk_level'] = 'CRITICAL'
            elif analysis['risk_score'] >= 60:
                analysis['risk_level'] = 'HIGH'
            elif analysis['risk_score'] >= 40:
                analysis['risk_level'] = 'MEDIUM'
            elif analysis['risk_score'] >= 20:
                analysis['risk_level'] = 'LOW'
            else:
                analysis['risk_level'] = 'MINIMAL'
            
            analysis['is_suspicious'] = analysis['risk_score'] >= 60
            
            # Generate enhanced recommendations
            if analysis['security_issues']:
                analysis['recommendations'].append('Review and validate app permissions')
                analysis['recommendations'].append('Verify app source and developer authenticity')
                analysis['recommendations'].append('Consider using official app store versions')
                
                if obfuscation_analysis.get('is_obfuscated'):
                    analysis['recommendations'].append('Exercise extreme caution - app uses obfuscation techniques')
                
                if string_analysis.get('hardcoded_secrets'):
                    analysis['recommendations'].append('App contains hardcoded secrets - potential data breach risk')
                
                if code_analysis.get('anti_analysis'):
                    analysis['recommendations'].append('App actively tries to evade analysis - likely malicious')
            
            return analysis
            
        except Exception as e:
            return {'error': f'Security analysis failed: {str(e)}'}
