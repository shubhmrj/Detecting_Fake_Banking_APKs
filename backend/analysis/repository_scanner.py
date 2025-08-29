"""
APK Repository Scanner Module
Scans APK repositories and app stores for fake banking applications
"""

import asyncio
import aiohttp
import requests
from typing import Dict, List, Any, Optional
import json
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
import re
from bs4 import BeautifulSoup

class APKRepositoryScanner:
    """Scans APK repositories for suspicious banking applications"""
    
    def __init__(self):
        self.repositories = {
            'play_store': {
                'base_url': 'https://play.google.com/store/apps',
                'search_endpoint': '/search?q={query}&c=apps',
                'app_endpoint': '/details?id={package_id}'
            },
            'apkpure': {
                'base_url': 'https://apkpure.com',
                'search_endpoint': '/search?q={query}',
                'app_endpoint': '/{package_path}'
            },
            'apkmirror': {
                'base_url': 'https://apkmirror.com',
                'search_endpoint': '/apk-search/?q={query}',
                'app_endpoint': '/apk/{app_path}'
            }
        }
        
        # Banking-related search terms
        self.banking_keywords = [
            'bank', 'banking', 'mobile bank', 'online banking',
            'chase', 'bank of america', 'wells fargo', 'citi',
            'usaa', 'capital one', 'pnc', 'td bank',
            'payment', 'wallet', 'finance', 'money transfer'
        ]
        
        # Known legitimate banking apps
        self.legitimate_banking_apps = {
            'com.chase.sig.android': 'Chase Mobile',
            'com.bankofamerica.digitalwallet': 'Bank of America Mobile Banking',
            'com.wellsfargo.mobile.android': 'Wells Fargo Mobile',
            'com.usaa.mobile.android.usaa': 'USAA Mobile',
            'com.citi.citimobile': 'Citi Mobile',
            'com.capitalone.enterprisemobilebanking': 'Capital One Mobile',
            'com.pnc.ecommerce.mobile': 'PNC Mobile Banking'
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def scan_repositories(self, keywords: List[str] = None) -> Dict[str, Any]:
        """Scan multiple repositories for banking apps"""
        if not keywords:
            keywords = self.banking_keywords
        
        scan_results = {
            'timestamp': time.time(),
            'repositories_scanned': [],
            'total_apps_found': 0,
            'suspicious_apps': [],
            'legitimate_apps': [],
            'flagged_for_review': []
        }
        
        for repo_name, repo_config in self.repositories.items():
            print(f"Scanning {repo_name}...")
            
            try:
                repo_results = self._scan_repository(repo_name, repo_config, keywords)
                scan_results['repositories_scanned'].append(repo_name)
                scan_results['total_apps_found'] += len(repo_results['apps'])
                
                # Classify found apps
                for app in repo_results['apps']:
                    classification = self._classify_app(app)
                    
                    if classification['is_suspicious']:
                        scan_results['suspicious_apps'].append(app)
                    elif classification['is_legitimate']:
                        scan_results['legitimate_apps'].append(app)
                    else:
                        scan_results['flagged_for_review'].append(app)
                        
            except Exception as e:
                print(f"Error scanning {repo_name}: {e}")
        
        return scan_results
    
    def _scan_repository(self, repo_name: str, repo_config: Dict[str, str], 
                        keywords: List[str]) -> Dict[str, Any]:
        """Scan a specific repository"""
        apps_found = []
        
        for keyword in keywords[:3]:  # Limit to first 3 keywords for demo
            try:
                search_url = repo_config['base_url'] + repo_config['search_endpoint'].format(query=keyword)
                
                if repo_name == 'play_store':
                    apps = self._scan_play_store(search_url, keyword)
                elif repo_name == 'apkpure':
                    apps = self._scan_apkpure(search_url, keyword)
                elif repo_name == 'apkmirror':
                    apps = self._scan_apkmirror(search_url, keyword)
                else:
                    apps = []
                
                apps_found.extend(apps)
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                print(f"Error searching {keyword} in {repo_name}: {e}")
        
        return {'apps': apps_found}
    
    def _scan_play_store(self, search_url: str, keyword: str) -> List[Dict[str, Any]]:
        """Scan Google Play Store (simulated for demo)"""
        apps = []
        
        # Simulate finding apps
        simulated_apps = [
            {
                'name': f'Mobile Banking - {keyword.title()}',
                'package_id': f'com.fake.{keyword.replace(" ", "")}.banking',
                'developer': 'Unknown Developer',
                'rating': 3.2,
                'downloads': '10,000+',
                'repository': 'play_store',
                'url': f'https://play.google.com/store/apps/details?id=com.fake.{keyword.replace(" ", "")}.banking',
                'icon_url': None,
                'description': f'Secure mobile banking for {keyword} customers'
            }
        ]
        
        return simulated_apps
    
    def _scan_apkpure(self, search_url: str, keyword: str) -> List[Dict[str, Any]]:
        """Scan APKPure repository (simulated)"""
        apps = []
        
        # Simulate APKPure results
        simulated_apps = [
            {
                'name': f'{keyword.title()} Banking App',
                'package_id': f'com.apkpure.{keyword.replace(" ", "")}.bank',
                'developer': 'Third Party Dev',
                'version': '2.1.0',
                'repository': 'apkpure',
                'url': f'https://apkpure.com/{keyword.replace(" ", "-")}-banking',
                'download_url': f'https://apkpure.com/download/{keyword.replace(" ", "-")}.apk',
                'file_size': '15.2 MB'
            }
        ]
        
        return simulated_apps
    
    def _scan_apkmirror(self, search_url: str, keyword: str) -> List[Dict[str, Any]]:
        """Scan APKMirror repository (simulated)"""
        apps = []
        
        # Simulate APKMirror results
        simulated_apps = [
            {
                'name': f'Secure {keyword.title()} Mobile',
                'package_id': f'com.mirror.{keyword.replace(" ", "")}.secure',
                'developer': 'Mirror Banking Inc',
                'version': '1.8.5',
                'repository': 'apkmirror',
                'url': f'https://apkmirror.com/apk/{keyword.replace(" ", "-")}-secure/',
                'upload_date': '2024-01-15'
            }
        ]
        
        return simulated_apps
    
    def _classify_app(self, app: Dict[str, Any]) -> Dict[str, Any]:
        """Classify app as legitimate, suspicious, or needs review"""
        classification = {
            'is_legitimate': False,
            'is_suspicious': False,
            'needs_review': True,
            'risk_factors': [],
            'confidence': 0.0
        }
        
        package_id = app.get('package_id', '')
        app_name = app.get('name', '')
        developer = app.get('developer', '')
        repository = app.get('repository', '')
        
        # Check if it's a known legitimate app
        if package_id in self.legitimate_banking_apps:
            classification['is_legitimate'] = True
            classification['needs_review'] = False
            classification['confidence'] = 0.95
            return classification
        
        # Suspicious indicators
        risk_score = 0
        
        # Package name analysis
        if self._is_suspicious_package_name(package_id):
            risk_score += 30
            classification['risk_factors'].append('Suspicious package name')
        
        # Developer analysis
        if self._is_suspicious_developer(developer):
            risk_score += 25
            classification['risk_factors'].append('Unknown/suspicious developer')
        
        # Repository analysis
        if repository != 'play_store':
            risk_score += 20
            classification['risk_factors'].append('Third-party repository')
        
        # App name analysis
        if self._is_suspicious_app_name(app_name):
            risk_score += 15
            classification['risk_factors'].append('Generic/suspicious app name')
        
        # Rating analysis (if available)
        rating = app.get('rating', 5.0)
        if isinstance(rating, (int, float)) and rating < 3.0:
            risk_score += 10
            classification['risk_factors'].append('Low user rating')
        
        # Classification based on risk score
        if risk_score >= 60:
            classification['is_suspicious'] = True
            classification['needs_review'] = False
        elif risk_score >= 30:
            classification['needs_review'] = True
        else:
            classification['is_legitimate'] = True
            classification['needs_review'] = False
        
        classification['confidence'] = min(risk_score / 100.0, 0.95)
        
        return classification
    
    def _is_suspicious_package_name(self, package_id: str) -> bool:
        """Check if package name is suspicious"""
        if not package_id:
            return True
        
        suspicious_patterns = [
            r'^com\.android\.',  # Fake system apps
            r'^android\.',       # Fake Android apps
            r'^com\.google\.',   # Fake Google apps
            r'^com\.fake\.',     # Obviously fake
            r'^com\.test\.',     # Test packages
            r'^com\.temp\.',     # Temporary packages
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, package_id):
                return True
        
        # Check for very short or very long package names
        if len(package_id) < 10 or len(package_id) > 100:
            return True
        
        # Check for random-looking package names
        parts = package_id.split('.')
        if len(parts) < 2:
            return True
        
        return False
    
    def _is_suspicious_developer(self, developer: str) -> bool:
        """Check if developer name is suspicious"""
        if not developer:
            return True
        
        suspicious_developers = [
            'unknown', 'anonymous', 'test', 'temp', 'fake',
            'developer', 'user', 'admin', 'root'
        ]
        
        developer_lower = developer.lower()
        for sus_dev in suspicious_developers:
            if sus_dev in developer_lower:
                return True
        
        # Check for very short developer names
        if len(developer) < 3:
            return True
        
        return False
    
    def _is_suspicious_app_name(self, app_name: str) -> bool:
        """Check if app name is suspicious"""
        if not app_name:
            return True
        
        # Generic banking app names that might be fake
        generic_patterns = [
            r'^mobile banking$',
            r'^banking app$',
            r'^secure bank$',
            r'^bank mobile$',
            r'^online banking$'
        ]
        
        app_name_lower = app_name.lower()
        for pattern in generic_patterns:
            if re.match(pattern, app_name_lower):
                return True
        
        return False
    
    def _calculate_overall_risk(self, scan_results: Dict[str, Any]) -> str:
        """Calculate overall risk level from scan results"""
        total_apps = scan_results['total_apps_found']
        suspicious_apps = len(scan_results['suspicious_apps'])
        
        if total_apps == 0:
            return 'LOW'
        
        risk_ratio = suspicious_apps / total_apps
        
        if risk_ratio >= 0.5:
            return 'CRITICAL'
        elif risk_ratio >= 0.3:
            return 'HIGH'
        elif risk_ratio >= 0.1:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        if scan_results['suspicious_apps']:
            recommendations.append("Immediately investigate and remove suspicious banking apps")
            recommendations.append("Implement stricter app store review processes")
        
        if scan_results['flagged_for_review']:
            recommendations.append("Conduct manual review of flagged applications")
        
        recommendations.extend([
            "Monitor repositories regularly for new threats",
            "Educate users about downloading apps only from official sources",
            "Implement automated scanning for new app submissions"
        ])
        
        return recommendations
    
    def generate_scan_report(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive scan report"""
        report = {
            'scan_summary': {
                'timestamp': scan_results['timestamp'],
                'repositories_scanned': len(scan_results['repositories_scanned']),
                'total_apps_found': scan_results['total_apps_found'],
                'suspicious_apps_count': len(scan_results['suspicious_apps']),
                'legitimate_apps_count': len(scan_results['legitimate_apps']),
                'flagged_for_review_count': len(scan_results['flagged_for_review'])
            },
            'threat_assessment': {
                'risk_level': self._calculate_overall_risk(scan_results),
                'top_threats': scan_results['suspicious_apps'][:5],
                'recommendations': self._generate_recommendations(scan_results)
            },
            'detailed_findings': {
                'suspicious_apps': scan_results['suspicious_apps'],
                'legitimate_apps': scan_results['legitimate_apps'],
                'flagged_for_review': scan_results['flagged_for_review']
            }
        }
        
        return report
