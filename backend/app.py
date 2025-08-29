"""
Backend API for Fake Banking APK Detection System
Flask-based REST API with simplified dependencies
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
import json
import hashlib
import zipfile
from pathlib import Path
import sqlite3
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend communication

# Configuration
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
DATABASE_PATH = 'data/apk_analysis.db'

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)
os.makedirs('data', exist_ok=True)

# Initialize database
def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS apk_analysis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            package_name TEXT,
            app_name TEXT,
            file_hash TEXT,
            risk_score REAL,
            is_suspicious BOOLEAN,
            analysis_data TEXT,
            timestamp TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

init_database()

class SimpleAPKAnalyzer:
    """Simplified APK analyzer without heavy dependencies"""
    
    def __init__(self):
        self.suspicious_permissions = {
            'android.permission.SEND_SMS': 'high',
            'android.permission.READ_SMS': 'high',
            'android.permission.RECEIVE_SMS': 'high',
            'android.permission.CALL_PHONE': 'medium',
            'android.permission.READ_PHONE_STATE': 'medium',
            'android.permission.SYSTEM_ALERT_WINDOW': 'high',
            'android.permission.DEVICE_ADMIN': 'high',
            'android.permission.GET_ACCOUNTS': 'high',
            'android.permission.ACCESS_FINE_LOCATION': 'medium',
            'android.permission.CAMERA': 'medium',
            'android.permission.RECORD_AUDIO': 'medium'
        }
        
        self.banking_keywords = [
            'bank', 'banking', 'finance', 'payment', 'wallet', 'money',
            'credit', 'debit', 'account', 'transaction', 'transfer'
        ]
    
    def analyze_apk(self, apk_path):
        """Analyze APK file and return results"""
        try:
            # Calculate file hash
            file_hash = self._calculate_hash(apk_path)
            
            # Extract basic info from APK
            apk_info = self._extract_apk_info(apk_path)
            
            # Analyze permissions
            permissions_analysis = self._analyze_permissions(apk_info.get('permissions', []))
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(apk_info, permissions_analysis)
            
            # Determine if suspicious
            is_suspicious = risk_score >= 60
            
            result = {
                'file_hash': file_hash,
                'package_name': apk_info.get('package_name', 'unknown'),
                'app_name': apk_info.get('app_name', 'unknown'),
                'version_name': apk_info.get('version_name', 'unknown'),
                'permissions': apk_info.get('permissions', []),
                'suspicious_permissions': permissions_analysis['suspicious'],
                'permission_count': len(apk_info.get('permissions', [])),
                'risk_score': risk_score,
                'is_suspicious': is_suspicious,
                'risk_level': self._get_risk_level(risk_score),
                'analysis_details': {
                    'has_banking_keywords': self._has_banking_keywords(apk_info.get('app_name', '')),
                    'suspicious_package_name': self._is_suspicious_package_name(apk_info.get('package_name', '')),
                    'permission_analysis': permissions_analysis
                }
            }
            
            return result
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_hash(self, file_path):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _extract_apk_info(self, apk_path):
        """Extract basic information from APK file"""
        info = {
            'package_name': 'unknown',
            'app_name': 'unknown',
            'version_name': 'unknown',
            'permissions': []
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Try to read AndroidManifest.xml
                if 'AndroidManifest.xml' in apk_zip.namelist():
                    manifest_data = apk_zip.read('AndroidManifest.xml')
                    # Note: This is binary XML, would need androguard for proper parsing
                    # For demo, we'll simulate the extraction
                    info = self._simulate_manifest_parsing(apk_path)
                
        except Exception as e:
            print(f"Error extracting APK info: {e}")
        
        return info
    
    def _simulate_manifest_parsing(self, apk_path):
        """Simulate manifest parsing for demo purposes"""
        filename = Path(apk_path).stem
        
        # Simulate different types of APKs based on filename patterns
        if 'chase' in filename.lower():
            return {
                'package_name': 'com.chase.sig.android',
                'app_name': 'Chase Mobile',
                'version_name': '5.2.1',
                'permissions': [
                    'android.permission.INTERNET',
                    'android.permission.ACCESS_NETWORK_STATE',
                    'android.permission.CAMERA',
                    'android.permission.ACCESS_FINE_LOCATION'
                ]
            }
        elif 'fake' in filename.lower() or 'malicious' in filename.lower():
            return {
                'package_name': 'com.fake.banking.app',
                'app_name': 'Secure Banking',
                'version_name': '1.0.0',
                'permissions': [
                    'android.permission.INTERNET',
                    'android.permission.SEND_SMS',
                    'android.permission.READ_SMS',
                    'android.permission.CALL_PHONE',
                    'android.permission.SYSTEM_ALERT_WINDOW',
                    'android.permission.DEVICE_ADMIN',
                    'android.permission.GET_ACCOUNTS',
                    'android.permission.ACCESS_FINE_LOCATION',
                    'android.permission.CAMERA',
                    'android.permission.RECORD_AUDIO'
                ]
            }
        else:
            return {
                'package_name': 'com.example.bankingapp',
                'app_name': 'Banking App',
                'version_name': '2.1.0',
                'permissions': [
                    'android.permission.INTERNET',
                    'android.permission.ACCESS_NETWORK_STATE',
                    'android.permission.ACCESS_FINE_LOCATION'
                ]
            }
    
    def _analyze_permissions(self, permissions):
        """Analyze permissions for suspicious patterns"""
        suspicious = []
        risk_score = 0
        
        for perm in permissions:
            if perm in self.suspicious_permissions:
                suspicious.append(perm)
                severity = self.suspicious_permissions[perm]
                if severity == 'high':
                    risk_score += 20
                elif severity == 'medium':
                    risk_score += 10
                else:
                    risk_score += 5
        
        return {
            'suspicious': suspicious,
            'risk_score': min(risk_score, 100),
            'suspicious_ratio': len(suspicious) / max(len(permissions), 1)
        }
    
    def _calculate_risk_score(self, apk_info, permissions_analysis):
        """Calculate overall risk score"""
        risk_score = permissions_analysis['risk_score']
        
        # Package name analysis
        if self._is_suspicious_package_name(apk_info.get('package_name', '')):
            risk_score += 25
        
        # App name analysis
        if not self._has_banking_keywords(apk_info.get('app_name', '')):
            risk_score += 10
        
        # Permission count
        perm_count = len(apk_info.get('permissions', []))
        if perm_count > 20:
            risk_score += 15
        elif perm_count > 15:
            risk_score += 10
        
        return min(risk_score, 100)
    
    def _is_suspicious_package_name(self, package_name):
        """Check if package name is suspicious"""
        if not package_name or len(package_name) < 10:
            return True
        
        suspicious_patterns = ['fake', 'test', 'temp', 'malicious', 'android.', 'com.android.']
        return any(pattern in package_name.lower() for pattern in suspicious_patterns)
    
    def _has_banking_keywords(self, app_name):
        """Check if app name contains banking keywords"""
        if not app_name:
            return False
        
        app_name_lower = app_name.lower()
        return any(keyword in app_name_lower for keyword in self.banking_keywords)
    
    def _get_risk_level(self, risk_score):
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

# Initialize analyzer
analyzer = SimpleAPKAnalyzer()

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Fake Banking APK Detection API is running',
        'version': '1.0.0'
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_apk():
    """Analyze uploaded APK file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.lower().endswith('.apk'):
        return jsonify({'error': 'File must be an APK'}), 400
    
    try:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
            file.save(tmp_file.name)
            
            # Analyze APK
            analysis_result = analyzer.analyze_apk(tmp_file.name)
            
            # Store in database
            store_analysis_result(file.filename, analysis_result)
            
            # Clean up temporary file
            os.unlink(tmp_file.name)
            
            return jsonify({
                'status': 'success',
                'filename': file.filename,
                'analysis': analysis_result
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    """Scan APK from URL"""
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required'}), 400
    
    url = data['url']
    
    try:
        # Simulate URL analysis for demo
        url_analysis = analyze_url(url)
        
        return jsonify({
            'status': 'success',
            'url': url,
            'analysis': url_analysis
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_analysis_history():
    """Get analysis history"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT filename, package_name, app_name, risk_score, is_suspicious, timestamp
            FROM apk_analysis
            ORDER BY timestamp DESC
            LIMIT 50
        ''')
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'filename': row[0],
                'package_name': row[1],
                'app_name': row[2],
                'risk_score': row[3],
                'is_suspicious': bool(row[4]),
                'timestamp': row[5]
            })
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'history': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get system statistics"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Total analyses
        cursor.execute('SELECT COUNT(*) FROM apk_analysis')
        total_analyses = cursor.fetchone()[0]
        
        # Suspicious APKs
        cursor.execute('SELECT COUNT(*) FROM apk_analysis WHERE is_suspicious = 1')
        suspicious_count = cursor.fetchone()[0]
        
        # Risk level distribution
        cursor.execute('''
            SELECT 
                CASE 
                    WHEN risk_score >= 80 THEN 'CRITICAL'
                    WHEN risk_score >= 60 THEN 'HIGH'
                    WHEN risk_score >= 40 THEN 'MEDIUM'
                    WHEN risk_score >= 20 THEN 'LOW'
                    ELSE 'MINIMAL'
                END as risk_level,
                COUNT(*) as count
            FROM apk_analysis
            GROUP BY risk_level
        ''')
        
        risk_distribution = dict(cursor.fetchall())
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'statistics': {
                'total_analyses': total_analyses,
                'suspicious_count': suspicious_count,
                'legitimate_count': total_analyses - suspicious_count,
                'risk_distribution': risk_distribution
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def store_analysis_result(filename, analysis_result):
    """Store analysis result in database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO apk_analysis 
            (filename, package_name, app_name, file_hash, risk_score, is_suspicious, analysis_data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            filename,
            analysis_result.get('package_name'),
            analysis_result.get('app_name'),
            analysis_result.get('file_hash'),
            analysis_result.get('risk_score'),
            analysis_result.get('is_suspicious'),
            json.dumps(analysis_result),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error storing analysis result: {e}")

def analyze_url(url):
    """Analyze URL for legitimacy (simplified version)"""
    suspicious_domains = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
        'ngrok.io', 'serveo.net', 'apkpure.com'
    ]
    
    legitimate_domains = [
        'play.google.com', 'apps.apple.com', 'samsung.com',
        'chase.com', 'bankofamerica.com', 'wellsfargo.com'
    ]
    
    risk_score = 0
    risk_factors = []
    
    # Check domain
    for sus_domain in suspicious_domains:
        if sus_domain in url.lower():
            risk_score += 40
            risk_factors.append(f'Suspicious domain: {sus_domain}')
    
    is_legitimate = any(legit_domain in url.lower() for legit_domain in legitimate_domains)
    
    if is_legitimate:
        risk_score = max(0, risk_score - 30)
        risk_factors.append('Legitimate domain detected')
    
    # Check for HTTPS
    if not url.startswith('https://'):
        risk_score += 20
        risk_factors.append('Non-HTTPS URL')
    
    return {
        'url': url,
        'risk_score': min(risk_score, 100),
        'is_suspicious': risk_score >= 50,
        'risk_level': analyzer._get_risk_level(risk_score),
        'risk_factors': risk_factors,
        'is_legitimate_source': is_legitimate
    }

if __name__ == '__main__':
    print("Starting Fake Banking APK Detection Backend API...")
    print("API will be available at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
