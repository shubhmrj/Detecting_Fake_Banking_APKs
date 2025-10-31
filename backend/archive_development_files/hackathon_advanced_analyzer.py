"""
Hackathon Solution: Advanced Metadata and Code Analysis Engine
Provides deep APK analysis including code patterns, API usage, and behavioral indicators
"""

import os
import sys
import json
import hashlib
import zipfile
import sqlite3
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import xml.etree.ElementTree as ET

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    print("[WARNING] Androguard not available - using fallback analysis")

class HackathonAdvancedAnalyzer:
    """
    Advanced APK analysis engine for comprehensive threat detection
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.analysis_db = self.base_dir / "data" / "hackathon_analysis.db"
        
        # Banking-specific patterns
        self.banking_keywords = [
            'bank', 'banking', 'finance', 'payment', 'wallet', 'money',
            'transfer', 'account', 'balance', 'transaction', 'credit',
            'debit', 'loan', 'investment', 'insurance', 'netbanking'
        ]
        
        # Suspicious API patterns
        self.suspicious_apis = [
            'sendSMS', 'getDeviceId', 'getSubscriberId', 'getLine1Number',
            'getNetworkOperator', 'getSimOperator', 'getLocation',
            'startService', 'bindService', 'registerReceiver',
            'requestPermissions', 'checkSelfPermission'
        ]
        
        # Malicious code patterns
        self.malicious_patterns = [
            r'Runtime\.getRuntime\(\)\.exec',
            r'ProcessBuilder',
            r'reflection\.',
            r'DexClassLoader',
            r'PathClassLoader',
            r'URLClassLoader',
            r'System\.loadLibrary',
            r'native.*method',
            r'JNI.*call',
            r'root.*check',
            r'su.*command'
        ]
        
        # Setup analysis database
        self.setup_analysis_database()
        
        print("[OK] Advanced Analyzer initialized")
    
    def setup_analysis_database(self):
        """Setup advanced analysis database"""
        conn = sqlite3.connect(self.analysis_db)
        cursor = conn.cursor()
        
        # Advanced analysis results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS advanced_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_path TEXT NOT NULL,
                apk_hash TEXT NOT NULL,
                analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                -- Metadata analysis
                package_name TEXT,
                app_name TEXT,
                version_name TEXT,
                version_code INTEGER,
                min_sdk_version INTEGER,
                target_sdk_version INTEGER,
                
                -- Code analysis
                total_classes INTEGER,
                total_methods INTEGER,
                native_methods INTEGER,
                reflection_usage INTEGER,
                dynamic_loading INTEGER,
                
                -- API usage analysis
                suspicious_api_count INTEGER,
                banking_api_usage INTEGER,
                network_api_usage INTEGER,
                sms_api_usage INTEGER,
                location_api_usage INTEGER,
                
                -- Pattern analysis
                malicious_pattern_count INTEGER,
                obfuscation_indicators INTEGER,
                encryption_usage INTEGER,
                
                -- Banking-specific analysis
                banking_keyword_count INTEGER,
                fake_banking_indicators INTEGER,
                legitimate_banking_score REAL,
                
                -- Risk assessment
                code_complexity_score REAL,
                suspicious_behavior_score REAL,
                overall_risk_score REAL,
                
                -- Analysis metadata
                analysis_duration REAL,
                analysis_method TEXT,
                error_count INTEGER
            )
        ''')
        
        # Code patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detected_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                pattern_type TEXT,
                pattern_name TEXT,
                pattern_description TEXT,
                severity TEXT,
                location TEXT,
                FOREIGN KEY (analysis_id) REFERENCES advanced_analysis (id)
            )
        ''')
        
        # API usage table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                api_name TEXT,
                api_category TEXT,
                usage_count INTEGER,
                risk_level TEXT,
                FOREIGN KEY (analysis_id) REFERENCES advanced_analysis (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        print("[OK] Advanced analysis database initialized")
    
    def analyze_apk_advanced(self, apk_path: str) -> Dict:
        """
        Perform comprehensive advanced APK analysis
        """
        start_time = datetime.now()
        
        print(f"\n[ADVANCED ANALYSIS] {Path(apk_path).name}")
        
        try:
            # Calculate APK hash
            apk_hash = self.calculate_file_hash(apk_path)
            
            # Initialize analysis results
            analysis_results = {
                'apk_path': apk_path,
                'apk_hash': apk_hash,
                'analysis_timestamp': start_time.isoformat(),
                'success': True,
                'error_messages': []
            }
            
            # Perform different analysis components
            metadata_results = self.analyze_metadata(apk_path)
            code_results = self.analyze_code_patterns(apk_path)
            api_results = self.analyze_api_usage(apk_path)
            banking_results = self.analyze_banking_indicators(apk_path)
            
            # Combine results
            analysis_results.update(metadata_results)
            analysis_results.update(code_results)
            analysis_results.update(api_results)
            analysis_results.update(banking_results)
            
            # Calculate risk scores
            risk_scores = self.calculate_risk_scores(analysis_results)
            analysis_results.update(risk_scores)
            
            # Calculate analysis duration
            end_time = datetime.now()
            analysis_results['analysis_duration'] = (end_time - start_time).total_seconds()
            
            # Store results in database
            analysis_id = self.store_analysis_results(analysis_results)
            analysis_results['analysis_id'] = analysis_id
            
            print(f"[OK] Advanced analysis completed (Risk: {analysis_results['overall_risk_score']:.1f})")
            
            return analysis_results
            
        except Exception as e:
            error_msg = f"Advanced analysis failed: {str(e)}"
            print(f"[ERROR] {error_msg}")
            
            return {
                'apk_path': apk_path,
                'success': False,
                'error_messages': [error_msg],
                'analysis_duration': (datetime.now() - start_time).total_seconds()
            }
    
    def analyze_metadata(self, apk_path: str) -> Dict:
        """Analyze APK metadata"""
        results = {
            'package_name': None,
            'app_name': None,
            'version_name': None,
            'version_code': 0,
            'min_sdk_version': 0,
            'target_sdk_version': 0
        }
        
        try:
            if ANDROGUARD_AVAILABLE:
                # Use androguard for detailed analysis
                apk = APK(apk_path)
                results.update({
                    'package_name': apk.get_package(),
                    'app_name': apk.get_app_name(),
                    'version_name': apk.get_androidversion_name(),
                    'version_code': apk.get_androidversion_code(),
                    'min_sdk_version': apk.get_min_sdk_version(),
                    'target_sdk_version': apk.get_target_sdk_version()
                })
            else:
                # Fallback: Parse AndroidManifest.xml directly
                results.update(self.parse_manifest_fallback(apk_path))
                
        except Exception as e:
            print(f"[WARNING] Metadata analysis error: {str(e)}")
        
        return results
    
    def analyze_code_patterns(self, apk_path: str) -> Dict:
        """Analyze code patterns and structure"""
        results = {
            'total_classes': 0,
            'total_methods': 0,
            'native_methods': 0,
            'reflection_usage': 0,
            'dynamic_loading': 0,
            'malicious_pattern_count': 0,
            'obfuscation_indicators': 0,
            'encryption_usage': 0,
            'detected_patterns': []
        }
        
        try:
            if ANDROGUARD_AVAILABLE:
                # Use androguard for code analysis
                results.update(self.analyze_code_with_androguard(apk_path))
            else:
                # Fallback: Basic file analysis
                results.update(self.analyze_code_fallback(apk_path))
                
        except Exception as e:
            print(f"[WARNING] Code analysis error: {str(e)}")
        
        return results
    
    def analyze_api_usage(self, apk_path: str) -> Dict:
        """Analyze API usage patterns"""
        results = {
            'suspicious_api_count': 0,
            'banking_api_usage': 0,
            'network_api_usage': 0,
            'sms_api_usage': 0,
            'location_api_usage': 0,
            'api_usage_details': []
        }
        
        try:
            if ANDROGUARD_AVAILABLE:
                results.update(self.analyze_apis_with_androguard(apk_path))
            else:
                results.update(self.analyze_apis_fallback(apk_path))
                
        except Exception as e:
            print(f"[WARNING] API analysis error: {str(e)}")
        
        return results
    
    def analyze_banking_indicators(self, apk_path: str) -> Dict:
        """Analyze banking-specific indicators"""
        results = {
            'banking_keyword_count': 0,
            'fake_banking_indicators': 0,
            'legitimate_banking_score': 0.0
        }
        
        try:
            # Extract strings from APK
            strings = self.extract_apk_strings(apk_path)
            
            # Count banking keywords
            banking_count = 0
            for string in strings:
                for keyword in self.banking_keywords:
                    if keyword.lower() in string.lower():
                        banking_count += 1
            
            results['banking_keyword_count'] = banking_count
            
            # Detect fake banking indicators
            fake_indicators = 0
            
            # Check for suspicious banking patterns
            suspicious_banking_patterns = [
                r'fake.*bank',
                r'phishing.*bank',
                r'clone.*bank',
                r'duplicate.*bank',
                r'mirror.*bank'
            ]
            
            for string in strings:
                for pattern in suspicious_banking_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        fake_indicators += 1
            
            results['fake_banking_indicators'] = fake_indicators
            
            # Calculate legitimate banking score
            if banking_count > 0:
                # Higher score for more banking keywords, lower for fake indicators
                results['legitimate_banking_score'] = max(0, min(100, 
                    (banking_count * 10) - (fake_indicators * 20)
                ))
            
        except Exception as e:
            print(f"[WARNING] Banking analysis error: {str(e)}")
        
        return results
    
    def analyze_code_with_androguard(self, apk_path: str) -> Dict:
        """Analyze code using androguard"""
        results = {
            'total_classes': 0,
            'total_methods': 0,
            'native_methods': 0,
            'reflection_usage': 0,
            'dynamic_loading': 0,
            'detected_patterns': []
        }
        
        try:
            apk = APK(apk_path)
            dex = DalvikVMFormat(apk.get_dex())
            analysis = Analysis(dex)
            
            # Count classes and methods
            results['total_classes'] = len(dex.get_classes())
            
            total_methods = 0
            native_methods = 0
            reflection_usage = 0
            dynamic_loading = 0
            
            for cls in dex.get_classes():
                for method in cls.get_methods():
                    total_methods += 1
                    
                    # Check for native methods
                    if method.get_access_flags() & 0x100:  # ACC_NATIVE
                        native_methods += 1
                    
                    # Analyze method code for patterns
                    try:
                        method_analysis = analysis.get_method(method)
                        if method_analysis:
                            code = method_analysis.get_method().get_code()
                            if code:
                                bytecode = code.get_bc()
                                
                                # Check for reflection usage
                                if 'invoke-virtual' in str(bytecode) and 'java/lang/reflect' in str(bytecode):
                                    reflection_usage += 1
                                
                                # Check for dynamic loading
                                if any(pattern in str(bytecode) for pattern in ['DexClassLoader', 'PathClassLoader']):
                                    dynamic_loading += 1
                    except:
                        pass
            
            results.update({
                'total_methods': total_methods,
                'native_methods': native_methods,
                'reflection_usage': reflection_usage,
                'dynamic_loading': dynamic_loading
            })
            
        except Exception as e:
            print(f"[WARNING] Androguard code analysis error: {str(e)}")
        
        return results
    
    def analyze_code_fallback(self, apk_path: str) -> Dict:
        """Fallback code analysis without androguard"""
        results = {
            'total_classes': 0,
            'total_methods': 0,
            'malicious_pattern_count': 0,
            'detected_patterns': []
        }
        
        try:
            # Extract and analyze DEX files
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                dex_files = [f for f in apk_zip.namelist() if f.endswith('.dex')]
                
                for dex_file in dex_files:
                    dex_data = apk_zip.read(dex_file)
                    
                    # Simple pattern matching in DEX data
                    dex_string = str(dex_data)
                    
                    # Count malicious patterns
                    pattern_count = 0
                    detected_patterns = []
                    
                    for pattern in self.malicious_patterns:
                        matches = len(re.findall(pattern, dex_string, re.IGNORECASE))
                        if matches > 0:
                            pattern_count += matches
                            detected_patterns.append({
                                'pattern': pattern,
                                'count': matches,
                                'location': dex_file
                            })
                    
                    results['malicious_pattern_count'] += pattern_count
                    results['detected_patterns'].extend(detected_patterns)
        
        except Exception as e:
            print(f"[WARNING] Fallback code analysis error: {str(e)}")
        
        return results
    
    def analyze_apis_with_androguard(self, apk_path: str) -> Dict:
        """Analyze API usage with androguard"""
        results = {
            'suspicious_api_count': 0,
            'api_usage_details': []
        }
        
        try:
            apk = APK(apk_path)
            dex = DalvikVMFormat(apk.get_dex())
            
            # Analyze API calls
            suspicious_count = 0
            api_details = []
            
            for cls in dex.get_classes():
                for method in cls.get_methods():
                    try:
                        if method.get_code():
                            bytecode = method.get_code().get_bc()
                            
                            for api in self.suspicious_apis:
                                if api in str(bytecode):
                                    suspicious_count += 1
                                    api_details.append({
                                        'api': api,
                                        'class': cls.get_name(),
                                        'method': method.get_name()
                                    })
                    except:
                        pass
            
            results.update({
                'suspicious_api_count': suspicious_count,
                'api_usage_details': api_details
            })
            
        except Exception as e:
            print(f"[WARNING] Androguard API analysis error: {str(e)}")
        
        return results
    
    def analyze_apis_fallback(self, apk_path: str) -> Dict:
        """Fallback API analysis"""
        results = {
            'suspicious_api_count': 0,
            'api_usage_details': []
        }
        
        try:
            strings = self.extract_apk_strings(apk_path)
            
            suspicious_count = 0
            for string in strings:
                for api in self.suspicious_apis:
                    if api in string:
                        suspicious_count += 1
            
            results['suspicious_api_count'] = suspicious_count
            
        except Exception as e:
            print(f"[WARNING] Fallback API analysis error: {str(e)}")
        
        return results
    
    def extract_apk_strings(self, apk_path: str) -> List[str]:
        """Extract strings from APK"""
        strings = []
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Extract strings from various files
                for file_info in apk_zip.filelist:
                    if file_info.filename.endswith(('.xml', '.dex', '.so')):
                        try:
                            file_data = apk_zip.read(file_info.filename)
                            # Extract printable strings
                            file_strings = re.findall(rb'[^\x00-\x1f\x7f-\xff]{4,}', file_data)
                            strings.extend([s.decode('utf-8', errors='ignore') for s in file_strings])
                        except:
                            pass
        
        except Exception as e:
            print(f"[WARNING] String extraction error: {str(e)}")
        
        return strings
    
    def parse_manifest_fallback(self, apk_path: str) -> Dict:
        """Parse AndroidManifest.xml as fallback"""
        results = {
            'package_name': None,
            'app_name': None,
            'version_name': None,
            'version_code': 0
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    # Basic parsing (would need proper AXML parser for full functionality)
                    manifest_str = str(manifest_data)
                    
                    # Extract package name using regex
                    package_match = re.search(r'package="([^"]+)"', manifest_str)
                    if package_match:
                        results['package_name'] = package_match.group(1)
        
        except Exception as e:
            print(f"[WARNING] Manifest parsing error: {str(e)}")
        
        return results
    
    def calculate_risk_scores(self, analysis_results: Dict) -> Dict:
        """Calculate comprehensive risk scores"""
        scores = {
            'code_complexity_score': 0.0,
            'suspicious_behavior_score': 0.0,
            'overall_risk_score': 0.0
        }
        
        try:
            # Code complexity score (0-100)
            complexity_factors = [
                analysis_results.get('native_methods', 0) * 2,
                analysis_results.get('reflection_usage', 0) * 3,
                analysis_results.get('dynamic_loading', 0) * 5,
                analysis_results.get('obfuscation_indicators', 0) * 4
            ]
            scores['code_complexity_score'] = min(100, sum(complexity_factors))
            
            # Suspicious behavior score (0-100)
            behavior_factors = [
                analysis_results.get('suspicious_api_count', 0) * 2,
                analysis_results.get('malicious_pattern_count', 0) * 5,
                analysis_results.get('fake_banking_indicators', 0) * 10
            ]
            scores['suspicious_behavior_score'] = min(100, sum(behavior_factors))
            
            # Overall risk score (weighted average)
            scores['overall_risk_score'] = (
                scores['code_complexity_score'] * 0.3 +
                scores['suspicious_behavior_score'] * 0.7
            )
            
        except Exception as e:
            print(f"[WARNING] Risk calculation error: {str(e)}")
        
        return scores
    
    def store_analysis_results(self, results: Dict) -> int:
        """Store analysis results in database"""
        conn = sqlite3.connect(self.analysis_db)
        cursor = conn.cursor()
        
        # Insert main analysis record
        cursor.execute('''
            INSERT INTO advanced_analysis (
                apk_path, apk_hash, package_name, app_name, version_name, version_code,
                min_sdk_version, target_sdk_version, total_classes, total_methods,
                native_methods, reflection_usage, dynamic_loading, suspicious_api_count,
                banking_api_usage, network_api_usage, sms_api_usage, location_api_usage,
                malicious_pattern_count, obfuscation_indicators, encryption_usage,
                banking_keyword_count, fake_banking_indicators, legitimate_banking_score,
                code_complexity_score, suspicious_behavior_score, overall_risk_score,
                analysis_duration, analysis_method, error_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            results.get('apk_path'),
            results.get('apk_hash'),
            results.get('package_name'),
            results.get('app_name'),
            results.get('version_name'),
            results.get('version_code', 0),
            results.get('min_sdk_version', 0),
            results.get('target_sdk_version', 0),
            results.get('total_classes', 0),
            results.get('total_methods', 0),
            results.get('native_methods', 0),
            results.get('reflection_usage', 0),
            results.get('dynamic_loading', 0),
            results.get('suspicious_api_count', 0),
            results.get('banking_api_usage', 0),
            results.get('network_api_usage', 0),
            results.get('sms_api_usage', 0),
            results.get('location_api_usage', 0),
            results.get('malicious_pattern_count', 0),
            results.get('obfuscation_indicators', 0),
            results.get('encryption_usage', 0),
            results.get('banking_keyword_count', 0),
            results.get('fake_banking_indicators', 0),
            results.get('legitimate_banking_score', 0.0),
            results.get('code_complexity_score', 0.0),
            results.get('suspicious_behavior_score', 0.0),
            results.get('overall_risk_score', 0.0),
            results.get('analysis_duration', 0.0),
            'androguard' if ANDROGUARD_AVAILABLE else 'fallback',
            len(results.get('error_messages', []))
        ))
        
        analysis_id = cursor.lastrowid
        
        # Store detected patterns
        for pattern in results.get('detected_patterns', []):
            cursor.execute('''
                INSERT INTO detected_patterns (analysis_id, pattern_type, pattern_name, pattern_description, severity, location)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                'malicious_code',
                pattern.get('pattern'),
                f"Detected {pattern.get('count', 1)} occurrences",
                'high',
                pattern.get('location', 'unknown')
            ))
        
        # Store API usage details
        for api_detail in results.get('api_usage_details', []):
            cursor.execute('''
                INSERT INTO api_usage (analysis_id, api_name, api_category, usage_count, risk_level)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                api_detail.get('api'),
                'suspicious',
                1,
                'medium'
            ))
        
        conn.commit()
        conn.close()
        
        return analysis_id
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def get_analysis_summary(self, analysis_id: int) -> Dict:
        """Get analysis summary by ID"""
        conn = sqlite3.connect(self.analysis_db)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM advanced_analysis WHERE id = ?
        ''', (analysis_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            # Convert to dictionary (simplified)
            return {
                'analysis_id': result[0],
                'apk_path': result[1],
                'overall_risk_score': result[-4],
                'analysis_timestamp': result[3]
            }
        
        return None

def main():
    """Test advanced analyzer"""
    analyzer = HackathonAdvancedAnalyzer()
    
    # Test with a sample APK if available
    test_apk_dir = Path(__file__).parent / "mp_police_datasets" / "legitimate" / "banking"
    
    if test_apk_dir.exists():
        apk_files = list(test_apk_dir.glob("*.apk"))
        if apk_files:
            test_apk = apk_files[0]
            print(f"Testing with: {test_apk.name}")
            
            results = analyzer.analyze_apk_advanced(str(test_apk))
            
            print(f"\nAnalysis Results:")
            print(f"- Package: {results.get('package_name', 'Unknown')}")
            print(f"- Risk Score: {results.get('overall_risk_score', 0):.1f}")
            print(f"- Banking Keywords: {results.get('banking_keyword_count', 0)}")
            print(f"- Suspicious APIs: {results.get('suspicious_api_count', 0)}")
            print(f"- Analysis Duration: {results.get('analysis_duration', 0):.2f}s")
        else:
            print("No APK files found for testing")
    else:
        print("Test APK directory not found")

if __name__ == "__main__":
    main()
