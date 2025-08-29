"""
Dynamic Analysis Module
Monitors network behavior and runtime characteristics of APK files
"""

import json
import time
import threading
import subprocess
import socket
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import requests
from urllib.parse import urlparse

@dataclass
class NetworkActivity:
    """Network activity record"""
    timestamp: float
    destination: str
    port: int
    protocol: str
    data_size: int
    is_encrypted: bool

@dataclass
class DynamicAnalysisResult:
    """Container for dynamic analysis results"""
    network_activities: List[NetworkActivity]
    suspicious_domains: List[str]
    data_exfiltration_detected: bool
    encryption_usage: Dict[str, int]
    runtime_permissions: List[str]
    behavioral_score: float

class DynamicAnalyzer:
    """Dynamic analysis for APK behavior monitoring"""
    
    # Known malicious/suspicious domains and patterns
    SUSPICIOUS_DOMAINS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',  # URL shorteners
        'ngrok.io', 'serveo.net',  # Tunneling services
        'duckdns.org', 'no-ip.com',  # Dynamic DNS
        'pastebin.com', 'hastebin.com',  # Text sharing
    ]
    
    SUSPICIOUS_PATTERNS = [
        'banking', 'paypal', 'amazon', 'google', 'microsoft',
        'login', 'secure', 'verify', 'account', 'update'
    ]
    
    def __init__(self):
        self.network_activities = []
        self.monitoring = False
        self.monitor_thread = None
    
    def analyze_network_behavior(self, apk_path: str, duration: int = 60) -> DynamicAnalysisResult:
        """
        Analyze network behavior of APK (simulated for hackathon demo)
        In a real implementation, this would use Android emulator or device
        """
        print(f"Starting dynamic analysis for {duration} seconds...")
        
        # Simulate network monitoring
        network_activities = self._simulate_network_monitoring(duration)
        
        # Analyze collected data
        suspicious_domains = self._identify_suspicious_domains(network_activities)
        data_exfiltration = self._detect_data_exfiltration(network_activities)
        encryption_usage = self._analyze_encryption_usage(network_activities)
        runtime_permissions = self._simulate_runtime_permissions()
        behavioral_score = self._calculate_behavioral_score(
            network_activities, suspicious_domains, data_exfiltration
        )
        
        return DynamicAnalysisResult(
            network_activities=network_activities,
            suspicious_domains=suspicious_domains,
            data_exfiltration_detected=data_exfiltration,
            encryption_usage=encryption_usage,
            runtime_permissions=runtime_permissions,
            behavioral_score=behavioral_score
        )
    
    def _simulate_network_monitoring(self, duration: int) -> List[NetworkActivity]:
        """
        Simulate network activity monitoring
        In real implementation, this would capture actual network traffic
        """
        activities = []
        
        # Simulate some network activities
        import random
        
        domains = [
            'api.legitimate-bank.com',
            'secure.banking-app.com',
            'suspicious-domain.tk',
            'bit.ly',
            'unknown-server.com',
            'google.com',
            'facebook.com'
        ]
        
        for i in range(random.randint(5, 20)):
            activity = NetworkActivity(
                timestamp=time.time() + i,
                destination=random.choice(domains),
                port=random.choice([80, 443, 8080, 9999]),
                protocol=random.choice(['HTTP', 'HTTPS', 'TCP']),
                data_size=random.randint(100, 10000),
                is_encrypted=random.choice([True, False])
            )
            activities.append(activity)
        
        return activities
    
    def _identify_suspicious_domains(self, activities: List[NetworkActivity]) -> List[str]:
        """Identify suspicious domains from network activities"""
        suspicious = set()
        
        for activity in activities:
            domain = activity.destination.lower()
            
            # Check against known suspicious domains
            for sus_domain in self.SUSPICIOUS_DOMAINS:
                if sus_domain in domain:
                    suspicious.add(domain)
            
            # Check for suspicious patterns
            for pattern in self.SUSPICIOUS_PATTERNS:
                if pattern in domain and not self._is_legitimate_domain(domain):
                    suspicious.add(domain)
            
            # Check for suspicious TLDs
            if any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.cf']):
                suspicious.add(domain)
        
        return list(suspicious)
    
    def _is_legitimate_domain(self, domain: str) -> bool:
        """Check if domain is from a legitimate organization"""
        legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'visa.com', 'mastercard.com', 'americanexpress.com'
        ]
        
        return any(legit in domain for legit in legitimate_domains)
    
    def _detect_data_exfiltration(self, activities: List[NetworkActivity]) -> bool:
        """Detect potential data exfiltration"""
        # Look for large outbound data transfers
        total_outbound = sum(activity.data_size for activity in activities)
        
        # Check for suspicious patterns
        if total_outbound > 50000:  # More than 50KB outbound
            return True
        
        # Check for connections to suspicious domains with data transfer
        for activity in activities:
            if (activity.destination in self._identify_suspicious_domains(activities) and 
                activity.data_size > 1000):
                return True
        
        return False
    
    def _analyze_encryption_usage(self, activities: List[NetworkActivity]) -> Dict[str, int]:
        """Analyze encryption usage patterns"""
        encryption_stats = {
            'encrypted_connections': 0,
            'unencrypted_connections': 0,
            'https_connections': 0,
            'http_connections': 0
        }
        
        for activity in activities:
            if activity.is_encrypted or activity.protocol == 'HTTPS':
                encryption_stats['encrypted_connections'] += 1
                if activity.protocol == 'HTTPS':
                    encryption_stats['https_connections'] += 1
            else:
                encryption_stats['unencrypted_connections'] += 1
                if activity.protocol == 'HTTP':
                    encryption_stats['http_connections'] += 1
        
        return encryption_stats
    
    def _simulate_runtime_permissions(self) -> List[str]:
        """Simulate runtime permission requests"""
        import random
        
        possible_permissions = [
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.READ_CONTACTS',
            'android.permission.CALL_PHONE',
            'android.permission.RECORD_AUDIO'
        ]
        
        # Randomly select some permissions that were requested at runtime
        return random.sample(possible_permissions, random.randint(0, 4))
    
    def _calculate_behavioral_score(self, activities: List[NetworkActivity], 
                                  suspicious_domains: List[str], 
                                  data_exfiltration: bool) -> float:
        """Calculate behavioral risk score (0-100)"""
        score = 0.0
        
        # Suspicious domain connections
        if suspicious_domains:
            score += min(len(suspicious_domains) * 15, 45)
        
        # Data exfiltration
        if data_exfiltration:
            score += 30
        
        # Unencrypted connections to external domains
        unencrypted_external = sum(1 for activity in activities 
                                 if not activity.is_encrypted and 
                                 not self._is_legitimate_domain(activity.destination))
        if unencrypted_external > 0:
            score += min(unencrypted_external * 5, 20)
        
        # High number of network connections
        if len(activities) > 15:
            score += 10
        
        # Connections to non-standard ports
        non_standard_ports = sum(1 for activity in activities 
                               if activity.port not in [80, 443])
        if non_standard_ports > 0:
            score += min(non_standard_ports * 3, 15)
        
        return min(score, 100.0)
    
    def start_real_time_monitoring(self):
        """Start real-time network monitoring (placeholder for real implementation)"""
        print("Real-time monitoring would be implemented here using:")
        print("- Android Debug Bridge (ADB)")
        print("- Network traffic capture tools")
        print("- Emulator integration")
        print("- Runtime behavior analysis")
    
    def analyze_api_calls(self, apk_path: str) -> Dict[str, Any]:
        """Analyze API calls made by the APK"""
        # This would integrate with tools like Frida for dynamic instrumentation
        api_analysis = {
            'sensitive_api_calls': [
                'TelephonyManager.getDeviceId()',
                'SmsManager.sendTextMessage()',
                'LocationManager.getLastKnownLocation()',
                'ContactsContract.CommonDataKinds.Phone'
            ],
            'crypto_api_usage': [
                'javax.crypto.Cipher',
                'java.security.MessageDigest'
            ],
            'network_api_calls': [
                'HttpURLConnection.connect()',
                'Socket.connect()'
            ]
        }
        
        return api_analysis
