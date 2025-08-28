"""
Report Generation Module
Creates detailed analysis reports for APK classification results
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

class ReportGenerator:
    """Generates comprehensive analysis reports"""
    
    def __init__(self):
        self.report_template = {
            'analysis_metadata': {},
            'apk_information': {},
            'static_analysis': {},
            'dynamic_analysis': {},
            'classification_result': {},
            'risk_assessment': {},
            'recommendations': []
        }
    
    def generate_report(self, analysis_result, prediction: Dict[str, Any], apk_path: str) -> Dict[str, Any]:
        """
        Generate comprehensive analysis report
        """
        report = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'apk_path': apk_path,
                'analyzer_version': '1.0.0',
                'analysis_duration': 'N/A'
            },
            
            'apk_information': {
                'package_name': analysis_result.package_name,
                'app_name': analysis_result.app_name,
                'version_name': analysis_result.version_name,
                'version_code': analysis_result.version_code,
                'file_hashes': analysis_result.file_hashes
            },
            
            'static_analysis': {
                'permissions': {
                    'total_count': len(analysis_result.permissions),
                    'all_permissions': analysis_result.permissions,
                    'suspicious_permissions': analysis_result.suspicious_permissions,
                    'suspicious_count': len(analysis_result.suspicious_permissions)
                },
                'components': {
                    'activities': len(analysis_result.activities),
                    'services': len(analysis_result.services),
                    'receivers': len(analysis_result.receivers)
                },
                'certificates': analysis_result.certificates,
                'network_security': analysis_result.network_security_config
            },
            
            'classification_result': {
                'is_fake': prediction.get('is_fake', False),
                'confidence': prediction.get('confidence', 0.0),
                'method': prediction.get('method', 'unknown'),
                'model_used': prediction.get('model_used', 'rule_based'),
                'probability_scores': {
                    'fake': prediction.get('probability_fake', 0.0),
                    'legitimate': prediction.get('probability_legitimate', 1.0)
                }
            },
            
            'risk_assessment': {
                'overall_risk_score': analysis_result.risk_score,
                'risk_level': self._get_risk_level(analysis_result.risk_score),
                'risk_factors': self._identify_risk_factors(analysis_result),
                'feature_analysis': analysis_result.features
            },
            
            'recommendations': self._generate_recommendations(analysis_result, prediction)
        }
        
        return report
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level"""
        if risk_score >= 80:
            return 'CRITICAL'
        elif risk_score >= 60:
            return 'HIGH'
        elif risk_score >= 40:
            return 'MEDIUM'
        elif risk_score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _identify_risk_factors(self, analysis_result) -> List[Dict[str, Any]]:
        """Identify specific risk factors"""
        risk_factors = []
        
        # Suspicious permissions
        if analysis_result.suspicious_permissions:
            risk_factors.append({
                'category': 'Permissions',
                'severity': 'HIGH',
                'description': f'App requests {len(analysis_result.suspicious_permissions)} suspicious permissions',
                'details': analysis_result.suspicious_permissions
            })
        
        # Self-signed certificate
        if analysis_result.features.get('has_self_signed_cert', False):
            risk_factors.append({
                'category': 'Certificate',
                'severity': 'MEDIUM',
                'description': 'App uses self-signed certificate',
                'details': 'Self-signed certificates are not verified by trusted authorities'
            })
        
        # Suspicious package name
        if analysis_result.features.get('package_name_suspicious', False):
            risk_factors.append({
                'category': 'Package Name',
                'severity': 'MEDIUM',
                'description': 'Package name appears suspicious',
                'details': f'Package: {analysis_result.package_name}'
            })
        
        # Excessive permissions
        if analysis_result.features.get('permission_count', 0) > 20:
            risk_factors.append({
                'category': 'Permissions',
                'severity': 'MEDIUM',
                'description': 'App requests excessive number of permissions',
                'details': f'Total permissions: {analysis_result.features.get("permission_count", 0)}'
            })
        
        # High suspicious permission ratio
        if analysis_result.features.get('suspicious_permission_ratio', 0) > 0.5:
            risk_factors.append({
                'category': 'Permissions',
                'severity': 'HIGH',
                'description': 'High ratio of suspicious permissions',
                'details': f'Ratio: {analysis_result.features.get("suspicious_permission_ratio", 0):.2f}'
            })
        
        return risk_factors
    
    def _generate_recommendations(self, analysis_result, prediction: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate security recommendations"""
        recommendations = []
        
        if prediction.get('is_fake', False):
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'DO NOT INSTALL',
                'description': 'This APK has been classified as fake/malicious and should not be installed'
            })
            
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Report to authorities',
                'description': 'Report this fake banking app to relevant cybersecurity authorities'
            })
        
        if analysis_result.suspicious_permissions:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Review permissions carefully',
                'description': 'This app requests suspicious permissions that may be used for malicious purposes'
            })
        
        if analysis_result.features.get('has_self_signed_cert', False):
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Verify app authenticity',
                'description': 'Self-signed certificates cannot be verified. Confirm app is from official source'
            })
        
        if not analysis_result.features.get('has_banking_keywords', False):
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Verify banking app legitimacy',
                'description': 'App does not contain typical banking keywords. Verify with official bank'
            })
        
        # General recommendations
        recommendations.append({
            'priority': 'LOW',
            'action': 'Download from official sources',
            'description': 'Always download banking apps from official app stores or bank websites'
        })
        
        recommendations.append({
            'priority': 'LOW',
            'action': 'Keep apps updated',
            'description': 'Regularly update banking apps to get latest security patches'
        })
        
        return recommendations
    
    def save_report(self, report: Dict[str, Any], file_path: str):
        """Save report to JSON file"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise Exception(f"Failed to save report: {str(e)}")
    
    def generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML version of the report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>APK Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .risk-critical { background-color: #ffebee; border-color: #f44336; }
                .risk-high { background-color: #fff3e0; border-color: #ff9800; }
                .risk-medium { background-color: #fff8e1; border-color: #ffc107; }
                .risk-low { background-color: #f1f8e9; border-color: #4caf50; }
                .fake { color: #d32f2f; font-weight: bold; }
                .legitimate { color: #388e3c; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f5f5f5; }
                .recommendation { margin: 10px 0; padding: 10px; border-left: 4px solid #2196f3; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>APK Security Analysis Report</h1>
                <p><strong>App:</strong> {app_name}</p>
                <p><strong>Package:</strong> {package_name}</p>
                <p><strong>Analysis Date:</strong> {timestamp}</p>
            </div>
            
            <div class="section">
                <h2>Classification Result</h2>
                <p class="{classification_class}">
                    <strong>Status:</strong> {classification_status}
                </p>
                <p><strong>Confidence:</strong> {confidence:.2f}</p>
                <p><strong>Risk Level:</strong> {risk_level}</p>
            </div>
            
            <div class="section">
                <h2>Risk Factors</h2>
                {risk_factors_html}
            </div>
            
            <div class="section">
                <h2>Permissions Analysis</h2>
                <p><strong>Total Permissions:</strong> {total_permissions}</p>
                <p><strong>Suspicious Permissions:</strong> {suspicious_permissions}</p>
                {permissions_table}
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                {recommendations_html}
            </div>
        </body>
        </html>
        """
        
        # Format the HTML with report data
        classification_class = "fake" if report['classification_result']['is_fake'] else "legitimate"
        classification_status = "FAKE/MALICIOUS" if report['classification_result']['is_fake'] else "LEGITIMATE"
        
        # Generate risk factors HTML
        risk_factors_html = ""
        for factor in report['risk_assessment']['risk_factors']:
            risk_factors_html += f"""
            <div class="risk-factor">
                <strong>{factor['category']} ({factor['severity']}):</strong> {factor['description']}
            </div>
            """
        
        # Generate permissions table
        permissions_table = "<table><tr><th>Permission</th><th>Status</th></tr>"
        for perm in report['static_analysis']['permissions']['all_permissions']:
            status = "Suspicious" if perm in report['static_analysis']['permissions']['suspicious_permissions'] else "Normal"
            permissions_table += f"<tr><td>{perm}</td><td>{status}</td></tr>"
        permissions_table += "</table>"
        
        # Generate recommendations HTML
        recommendations_html = ""
        for rec in report['recommendations']:
            recommendations_html += f"""
            <div class="recommendation">
                <strong>{rec['priority']}:</strong> {rec['action']}<br>
                {rec['description']}
            </div>
            """
        
        formatted_html = html_template.format(
            app_name=report['apk_information']['app_name'],
            package_name=report['apk_information']['package_name'],
            timestamp=report['analysis_metadata']['timestamp'],
            classification_class=classification_class,
            classification_status=classification_status,
            confidence=report['classification_result']['confidence'],
            risk_level=report['risk_assessment']['risk_level'],
            risk_factors_html=risk_factors_html,
            total_permissions=report['static_analysis']['permissions']['total_count'],
            suspicious_permissions=report['static_analysis']['permissions']['suspicious_count'],
            permissions_table=permissions_table,
            recommendations_html=recommendations_html
        )
        
        return formatted_html
    
    def save_html_report(self, report: Dict[str, Any], file_path: str):
        """Save HTML report to file"""
        html_content = self.generate_html_report(report)
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
        except Exception as e:
            raise Exception(f"Failed to save HTML report: {str(e)}")
    
    def generate_summary(self, report: Dict[str, Any]) -> str:
        """Generate a brief summary of the analysis"""
        classification = "FAKE/MALICIOUS" if report['classification_result']['is_fake'] else "LEGITIMATE"
        confidence = report['classification_result']['confidence']
        risk_level = report['risk_assessment']['risk_level']
        
        summary = f"""
APK Analysis Summary:
- App: {report['apk_information']['app_name']}
- Classification: {classification} (Confidence: {confidence:.2f})
- Risk Level: {risk_level}
- Suspicious Permissions: {report['static_analysis']['permissions']['suspicious_count']}
- Risk Factors: {len(report['risk_assessment']['risk_factors'])}
        """
        
        return summary.strip()
