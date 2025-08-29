"""
Dynamic APK Analysis with Sandbox Execution
Phase 4: Runtime Behavior Monitoring and Sandbox Analysis
"""

import os
import json
import time
import subprocess
import threading
import socket
import psutil
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import shutil
import re
from typing import Dict, List, Optional, Any

class DynamicAPKAnalyzer:
    """Dynamic analysis engine for APK runtime behavior monitoring"""
    
    def __init__(self):
        self.sandbox_dir = None
        self.emulator_port = 5554
        self.adb_path = "adb"  # Assumes ADB is in PATH
        self.analysis_timeout = 300  # 5 minutes max analysis time
        self.monitoring_active = False
        
        # Behavioral patterns to monitor
        self.suspicious_behaviors = {
            'network_connections': [],
            'file_operations': [],
            'api_calls': [],
            'permission_usage': [],
            'sms_operations': [],
            'phone_operations': [],
            'location_access': [],
            'crypto_operations': [],
            'root_detection': [],
            'anti_analysis': []
        }
        
        # Known malicious network indicators
        self.malicious_domains = [
            'bit.ly', 'tinyurl.com', 'ngrok.io', 'serveo.net',
            'duckdns.org', 'no-ip.com', 'ddns.net'
        ]
        
        # Suspicious API patterns
        self.suspicious_apis = [
            'getDeviceId', 'getSubscriberId', 'getSimSerialNumber',
            'sendTextMessage', 'Runtime.exec', 'ProcessBuilder',
            'TelephonyManager', 'LocationManager', 'getAccounts'
        ]
    
    def analyze_apk_dynamic(self, apk_path: str, timeout: int = 300) -> Dict[str, Any]:
        """Perform comprehensive dynamic analysis of APK"""
        try:
            analysis_start = datetime.now()
            self.analysis_timeout = timeout
            
            print(f"Starting dynamic analysis of: {apk_path}")
            
            # Setup sandbox environment
            sandbox_result = self._setup_sandbox()
            if not sandbox_result['success']:
                return {'error': f'Sandbox setup failed: {sandbox_result["error"]}'}
            
            # Install and launch APK
            install_result = self._install_apk(apk_path)
            if not install_result['success']:
                return {'error': f'APK installation failed: {install_result["error"]}'}
            
            package_name = install_result['package_name']
            
            # Start monitoring
            monitoring_thread = threading.Thread(
                target=self._start_monitoring,
                args=(package_name,)
            )
            monitoring_thread.daemon = True
            monitoring_thread.start()
            
            # Launch application
            launch_result = self._launch_app(package_name)
            
            # Perform automated interactions
            interaction_result = self._perform_interactions(package_name)
            
            # Wait for analysis completion or timeout
            time.sleep(min(timeout, 60))  # Monitor for up to 1 minute or specified timeout
            
            # Stop monitoring
            self.monitoring_active = False
            
            # Collect results
            behavior_analysis = self._analyze_behaviors()
            network_analysis = self._analyze_network_traffic()
            file_analysis = self._analyze_file_operations()
            
            # Cleanup
            self._cleanup_sandbox(package_name)
            
            # Build comprehensive result
            result = {
                'analysis_timestamp': analysis_start.isoformat(),
                'analysis_duration': (datetime.now() - analysis_start).total_seconds(),
                'package_name': package_name,
                'sandbox_setup': sandbox_result,
                'app_launch': launch_result,
                'interactions': interaction_result,
                'behavior_analysis': behavior_analysis,
                'network_analysis': network_analysis,
                'file_analysis': file_analysis,
                'risk_assessment': self._assess_dynamic_risk(behavior_analysis, network_analysis, file_analysis)
            }
            
            return result
            
        except Exception as e:
            return {'error': f'Dynamic analysis failed: {str(e)}'}
    
    def _setup_sandbox(self) -> Dict[str, Any]:
        """Setup isolated sandbox environment"""
        try:
            # Create temporary sandbox directory
            self.sandbox_dir = tempfile.mkdtemp(prefix='apk_sandbox_')
            
            # Check if ADB is available
            adb_check = subprocess.run([self.adb_path, 'version'], 
                                     capture_output=True, text=True, timeout=10)
            if adb_check.returncode != 0:
                return {'success': False, 'error': 'ADB not available'}
            
            # Check for connected devices/emulators
            devices_result = subprocess.run([self.adb_path, 'devices'], 
                                          capture_output=True, text=True, timeout=10)
            
            if 'device' not in devices_result.stdout and 'emulator' not in devices_result.stdout:
                # Try to start emulator (basic attempt)
                return {
                    'success': True, 
                    'warning': 'No Android device/emulator detected. Analysis will be limited.',
                    'sandbox_dir': self.sandbox_dir,
                    'has_device': False
                }
            
            return {
                'success': True,
                'sandbox_dir': self.sandbox_dir,
                'has_device': True,
                'adb_version': adb_check.stdout.strip()
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Sandbox setup error: {str(e)}'}
    
    def _install_apk(self, apk_path: str) -> Dict[str, Any]:
        """Install APK in sandbox environment"""
        try:
            # Extract package name from APK
            aapt_result = subprocess.run([
                'aapt', 'dump', 'badging', apk_path
            ], capture_output=True, text=True, timeout=30)
            
            package_name = None
            if aapt_result.returncode == 0:
                for line in aapt_result.stdout.split('\n'):
                    if line.startswith('package:'):
                        match = re.search(r"name='([^']+)'", line)
                        if match:
                            package_name = match.group(1)
                            break
            
            if not package_name:
                # Fallback: try to extract from filename or use generic name
                package_name = f"com.unknown.{int(time.time())}"
            
            # Install APK using ADB
            install_result = subprocess.run([
                self.adb_path, 'install', '-r', apk_path
            ], capture_output=True, text=True, timeout=60)
            
            if install_result.returncode != 0:
                return {
                    'success': False, 
                    'error': f'Installation failed: {install_result.stderr}',
                    'package_name': package_name
                }
            
            return {
                'success': True,
                'package_name': package_name,
                'install_output': install_result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Installation timeout'}
        except Exception as e:
            return {'success': False, 'error': f'Installation error: {str(e)}'}
    
    def _launch_app(self, package_name: str) -> Dict[str, Any]:
        """Launch the installed application"""
        try:
            # Get main activity
            activity_result = subprocess.run([
                self.adb_path, 'shell', 'pm', 'dump', package_name
            ], capture_output=True, text=True, timeout=30)
            
            main_activity = None
            if activity_result.returncode == 0:
                for line in activity_result.stdout.split('\n'):
                    if 'android.intent.action.MAIN' in line and 'Activity' in line:
                        # Extract activity name (simplified)
                        if package_name in line:
                            main_activity = f"{package_name}/.MainActivity"
                            break
            
            if not main_activity:
                main_activity = f"{package_name}/.MainActivity"
            
            # Launch application
            launch_result = subprocess.run([
                self.adb_path, 'shell', 'am', 'start', '-n', main_activity
            ], capture_output=True, text=True, timeout=30)
            
            # Wait for app to start
            time.sleep(3)
            
            return {
                'success': launch_result.returncode == 0,
                'main_activity': main_activity,
                'launch_output': launch_result.stdout if launch_result.returncode == 0 else launch_result.stderr
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Launch error: {str(e)}'}
    
    def _perform_interactions(self, package_name: str) -> Dict[str, Any]:
        """Perform automated interactions with the app"""
        try:
            interactions = []
            
            # Basic UI interactions
            interaction_commands = [
                # Tap center of screen
                ['shell', 'input', 'tap', '500', '1000'],
                # Swipe gestures
                ['shell', 'input', 'swipe', '300', '1000', '700', '1000'],
                # Back button
                ['shell', 'input', 'keyevent', 'KEYCODE_BACK'],
                # Menu button
                ['shell', 'input', 'keyevent', 'KEYCODE_MENU'],
                # Random text input
                ['shell', 'input', 'text', 'test123'],
            ]
            
            for i, cmd in enumerate(interaction_commands):
                try:
                    result = subprocess.run([self.adb_path] + cmd, 
                                          capture_output=True, text=True, timeout=10)
                    interactions.append({
                        'interaction': i + 1,
                        'command': ' '.join(cmd),
                        'success': result.returncode == 0
                    })
                    time.sleep(2)  # Wait between interactions
                except:
                    interactions.append({
                        'interaction': i + 1,
                        'command': ' '.join(cmd),
                        'success': False
                    })
            
            return {
                'success': True,
                'interactions_performed': len(interactions),
                'interactions': interactions
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Interaction error: {str(e)}'}
    
    def _start_monitoring(self, package_name: str):
        """Start comprehensive behavior monitoring"""
        self.monitoring_active = True
        
        # Monitor in separate threads
        threads = [
            threading.Thread(target=self._monitor_network_activity, args=(package_name,)),
            threading.Thread(target=self._monitor_file_operations, args=(package_name,)),
            threading.Thread(target=self._monitor_api_calls, args=(package_name,)),
            threading.Thread(target=self._monitor_system_calls, args=(package_name,))
        ]
        
        for thread in threads:
            thread.daemon = True
            thread.start()
    
    def _monitor_network_activity(self, package_name: str):
        """Monitor network connections and traffic"""
        try:
            while self.monitoring_active:
                # Monitor network connections
                netstat_result = subprocess.run([
                    self.adb_path, 'shell', 'netstat', '-an'
                ], capture_output=True, text=True, timeout=10)
                
                if netstat_result.returncode == 0:
                    connections = []
                    for line in netstat_result.stdout.split('\n'):
                        if 'ESTABLISHED' in line or 'LISTEN' in line:
                            connections.append(line.strip())
                    
                    self.suspicious_behaviors['network_connections'].extend(connections)
                
                time.sleep(5)
                
        except Exception as e:
            print(f"Network monitoring error: {e}")
    
    def _monitor_file_operations(self, package_name: str):
        """Monitor file system operations"""
        try:
            while self.monitoring_active:
                # Monitor file operations using strace (if available)
                try:
                    strace_result = subprocess.run([
                        self.adb_path, 'shell', 'ps | grep', package_name
                    ], capture_output=True, text=True, timeout=10)
                    
                    # Basic file monitoring - check for suspicious file access
                    ls_result = subprocess.run([
                        self.adb_path, 'shell', 'ls', '-la', '/data/data/' + package_name
                    ], capture_output=True, text=True, timeout=10)
                    
                    if ls_result.returncode == 0:
                        self.suspicious_behaviors['file_operations'].append({
                            'timestamp': datetime.now().isoformat(),
                            'operation': 'directory_listing',
                            'path': f'/data/data/{package_name}',
                            'details': ls_result.stdout[:500]  # Limit output
                        })
                
                except:
                    pass
                
                time.sleep(10)
                
        except Exception as e:
            print(f"File monitoring error: {e}")
    
    def _monitor_api_calls(self, package_name: str):
        """Monitor suspicious API calls"""
        try:
            while self.monitoring_active:
                # Monitor logcat for API calls
                logcat_result = subprocess.run([
                    self.adb_path, 'logcat', '-d', '-s', package_name
                ], capture_output=True, text=True, timeout=15)
                
                if logcat_result.returncode == 0:
                    for line in logcat_result.stdout.split('\n'):
                        for api in self.suspicious_apis:
                            if api in line:
                                self.suspicious_behaviors['api_calls'].append({
                                    'timestamp': datetime.now().isoformat(),
                                    'api': api,
                                    'log_entry': line[:200]  # Limit length
                                })
                
                time.sleep(8)
                
        except Exception as e:
            print(f"API monitoring error: {e}")
    
    def _monitor_system_calls(self, package_name: str):
        """Monitor system-level calls and behaviors"""
        try:
            while self.monitoring_active:
                # Check for root detection attempts
                su_check = subprocess.run([
                    self.adb_path, 'shell', 'ps | grep su'
                ], capture_output=True, text=True, timeout=10)
                
                if 'su' in su_check.stdout:
                    self.suspicious_behaviors['root_detection'].append({
                        'timestamp': datetime.now().isoformat(),
                        'behavior': 'su_process_check',
                        'details': su_check.stdout.strip()
                    })
                
                # Monitor for SMS/Phone operations
                dumpsys_result = subprocess.run([
                    self.adb_path, 'shell', 'dumpsys', 'telephony.registry'
                ], capture_output=True, text=True, timeout=15)
                
                if dumpsys_result.returncode == 0 and package_name in dumpsys_result.stdout:
                    self.suspicious_behaviors['phone_operations'].append({
                        'timestamp': datetime.now().isoformat(),
                        'behavior': 'telephony_access',
                        'details': 'App accessed telephony services'
                    })
                
                time.sleep(12)
                
        except Exception as e:
            print(f"System monitoring error: {e}")
    
    def _analyze_behaviors(self) -> Dict[str, Any]:
        """Analyze collected behavioral data"""
        analysis = {
            'total_behaviors': 0,
            'behavior_categories': {},
            'suspicious_score': 0,
            'behavior_timeline': []
        }
        
        for category, behaviors in self.suspicious_behaviors.items():
            count = len(behaviors)
            analysis['total_behaviors'] += count
            analysis['behavior_categories'][category] = {
                'count': count,
                'behaviors': behaviors[:10]  # Limit to first 10 entries
            }
            
            # Calculate suspicious score
            if category in ['root_detection', 'anti_analysis']:
                analysis['suspicious_score'] += count * 20
            elif category in ['sms_operations', 'phone_operations']:
                analysis['suspicious_score'] += count * 15
            elif category in ['api_calls', 'network_connections']:
                analysis['suspicious_score'] += count * 5
            else:
                analysis['suspicious_score'] += count * 2
        
        return analysis
    
    def _analyze_network_traffic(self) -> Dict[str, Any]:
        """Analyze network traffic patterns"""
        network_analysis = {
            'total_connections': 0,
            'suspicious_domains': [],
            'connection_patterns': [],
            'risk_score': 0
        }
        
        connections = self.suspicious_behaviors.get('network_connections', [])
        network_analysis['total_connections'] = len(connections)
        
        # Analyze connection patterns
        for connection in connections:
            # Check for suspicious domains
            for domain in self.malicious_domains:
                if domain in connection:
                    network_analysis['suspicious_domains'].append({
                        'domain': domain,
                        'connection': connection
                    })
                    network_analysis['risk_score'] += 25
            
            # Check for unusual ports
            if any(port in connection for port in [':4444', ':8080', ':9999']):
                network_analysis['risk_score'] += 15
        
        return network_analysis
    
    def _analyze_file_operations(self) -> Dict[str, Any]:
        """Analyze file system operations"""
        file_analysis = {
            'total_operations': 0,
            'suspicious_operations': [],
            'risk_score': 0
        }
        
        operations = self.suspicious_behaviors.get('file_operations', [])
        file_analysis['total_operations'] = len(operations)
        
        # Analyze for suspicious file operations
        for operation in operations:
            if isinstance(operation, dict):
                path = operation.get('path', '')
                if any(suspicious in path for suspicious in ['/system/', '/root/', '/su']):
                    file_analysis['suspicious_operations'].append(operation)
                    file_analysis['risk_score'] += 20
        
        return file_analysis
    
    def _assess_dynamic_risk(self, behavior_analysis: Dict, network_analysis: Dict, file_analysis: Dict) -> Dict[str, Any]:
        """Assess overall dynamic analysis risk"""
        total_risk = 0
        risk_factors = []
        
        # Behavior risk
        behavior_score = behavior_analysis.get('suspicious_score', 0)
        total_risk += min(behavior_score, 50)  # Cap at 50
        
        if behavior_score > 30:
            risk_factors.append('High suspicious behavior score')
        
        # Network risk
        network_score = network_analysis.get('risk_score', 0)
        total_risk += min(network_score, 30)  # Cap at 30
        
        if network_analysis.get('suspicious_domains'):
            risk_factors.append('Connections to suspicious domains')
        
        # File operation risk
        file_score = file_analysis.get('risk_score', 0)
        total_risk += min(file_score, 20)  # Cap at 20
        
        if file_analysis.get('suspicious_operations'):
            risk_factors.append('Suspicious file system access')
        
        # Determine risk level
        if total_risk >= 80:
            risk_level = 'CRITICAL'
        elif total_risk >= 60:
            risk_level = 'HIGH'
        elif total_risk >= 40:
            risk_level = 'MEDIUM'
        elif total_risk >= 20:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'total_risk_score': min(total_risk, 100),
            'risk_level': risk_level,
            'is_malicious': total_risk >= 60,
            'risk_factors': risk_factors,
            'behavior_contribution': behavior_score,
            'network_contribution': network_score,
            'file_contribution': file_score
        }
    
    def _cleanup_sandbox(self, package_name: str):
        """Clean up sandbox environment"""
        try:
            # Uninstall APK
            subprocess.run([
                self.adb_path, 'uninstall', package_name
            ], capture_output=True, timeout=30)
            
            # Remove sandbox directory
            if self.sandbox_dir and os.path.exists(self.sandbox_dir):
                shutil.rmtree(self.sandbox_dir)
            
        except Exception as e:
            print(f"Cleanup error: {e}")

# Simplified dynamic analyzer for environments without full Android setup
class SimplifiedDynamicAnalyzer:
    """Simplified dynamic analysis for environments without Android emulator"""
    
    def __init__(self):
        self.analysis_patterns = {
            'network_indicators': [
                'http://', 'https://', 'socket', 'connect',
                'ServerSocket', 'HttpURLConnection'
            ],
            'file_indicators': [
                'FileOutputStream', 'FileInputStream', 'openFileOutput',
                'getExternalStorageDirectory', 'getCacheDir'
            ],
            'telephony_indicators': [
                'TelephonyManager', 'SmsManager', 'sendTextMessage',
                'getDeviceId', 'getSubscriberId'
            ],
            'location_indicators': [
                'LocationManager', 'getLastKnownLocation', 'GPS_PROVIDER'
            ]
        }
    
    def simulate_dynamic_analysis(self, static_analysis_result: Dict) -> Dict[str, Any]:
        """Simulate dynamic analysis based on static analysis results"""
        try:
            simulation_result = {
                'analysis_type': 'simulated',
                'timestamp': datetime.now().isoformat(),
                'simulated_behaviors': {},
                'risk_assessment': {}
            }
            
            # Simulate behaviors based on static analysis
            api_calls = static_analysis_result.get('api_calls', {})
            urls = static_analysis_result.get('urls', {})
            permissions = static_analysis_result.get('permissions', {})
            
            # Simulate network behavior
            network_apis = api_calls.get('network_apis', [])
            http_urls = urls.get('http_urls', [])
            https_urls = urls.get('https_urls', [])
            
            simulation_result['simulated_behaviors']['network'] = {
                'likely_connections': len(network_apis) + len(http_urls) + len(https_urls),
                'suspicious_urls': urls.get('suspicious_urls', []),
                'risk_score': min(len(urls.get('suspicious_urls', [])) * 15, 50)
            }
            
            # Simulate telephony behavior
            telephony_apis = api_calls.get('telephony_apis', [])
            sms_permissions = any('SMS' in perm.get('name', '') for perm in permissions.get('permissions', []))
            
            simulation_result['simulated_behaviors']['telephony'] = {
                'likely_sms_usage': len(telephony_apis) > 0 or sms_permissions,
                'telephony_api_count': len(telephony_apis),
                'risk_score': len(telephony_apis) * 10 + (20 if sms_permissions else 0)
            }
            
            # Calculate overall simulated risk
            total_risk = 0
            for behavior in simulation_result['simulated_behaviors'].values():
                total_risk += behavior.get('risk_score', 0)
            
            simulation_result['risk_assessment'] = {
                'total_risk_score': min(total_risk, 100),
                'risk_level': 'HIGH' if total_risk >= 60 else 'MEDIUM' if total_risk >= 30 else 'LOW',
                'is_likely_malicious': total_risk >= 60,
                'confidence': 'simulated_analysis'
            }
            
            return simulation_result
            
        except Exception as e:
            return {'error': f'Simulation failed: {str(e)}'}

if __name__ == '__main__':
    # Example usage
    analyzer = DynamicAPKAnalyzer()
    
    # For testing without actual APK
    print("Dynamic APK Analyzer initialized")
    print("Requires Android SDK/ADB and emulator for full functionality")
