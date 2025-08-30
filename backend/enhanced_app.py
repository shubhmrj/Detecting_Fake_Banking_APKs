"""
Enhanced Backend API for Fake Banking APK Detection System
Phase 1: Real APK Analysis with Androguard
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
import json
import sqlite3
from datetime import datetime
from ml_trainer import APKMLTrainer
from dynamic_analyzer import DynamicAPKAnalyzer, SimplifiedDynamicAnalyzer
from sandbox_manager import SandboxManager
from behavior_monitor import BehaviorMonitor

app = Flask(__name__)
CORS(app)

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

# Initialize ML trainer
ml_trainer = APKMLTrainer()
try:
    ml_trainer.load_models()
    print("✅ ML models loaded successfully")
except:
    print("⚠️  Training new ML models...")
    data = ml_trainer.generate_synthetic_training_data(1000)
    ml_trainer.train_models(data)
    ml_trainer.save_models()
    print("✅ New ML models trained and saved")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'Enhanced Fake Banking APK Detection API is running',
        'version': '2.0.0',
        'features': ['Real APK Analysis', 'Certificate Validation', 'API Call Extraction', 'URL Analysis']
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_apk():
    """Analyze uploaded APK file with enhanced analysis"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'File must be an APK'}), 400
        
        # Save uploaded file temporarily
        temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{file.filename}")
        file.save(temp_path)
        
        try:
            from apk_analyzer import APKAnalyzer
            analyzer = APKAnalyzer()
            
            # Perform static analysis
            analysis_result = analyzer.analyze_apk(temp_path)
            
            # Add ML prediction
            ml_result = ml_trainer.predict(analysis_result)
            analysis_result['ml_prediction'] = ml_result
            
            if 'error' in analysis_result:
                return jsonify({
                    'status': 'error',
                    'filename': file.filename,
                    'error': analysis_result['error']
                }), 500
            
            # Add simulated dynamic analysis
            analysis_result['dynamic_analysis'] = {
                'status': 'simulated',
                'network_connections': [],
                'file_operations': [],
                'risk_score': analysis_result.get('security_analysis', {}).get('risk_score', 0)
            }
            
            # Store comprehensive analysis in database
            store_enhanced_analysis_result(file.filename, analysis_result)
            
            # Build response with enhanced data
            response_data = {
                'status': 'success',
                'filename': file.filename,
                'analysis': {
                    'file_hash': analysis_result['file_hash'],
                    'package_name': analysis_result['metadata']['package_name'],
                    'app_name': analysis_result['metadata']['app_name'],
                    'version_name': analysis_result['metadata']['version_name'],
                    'version_code': analysis_result['metadata']['version_code'],
                    'min_sdk': analysis_result['metadata']['min_sdk'],
                    'target_sdk': analysis_result['metadata']['target_sdk'],
                    'file_size': analysis_result['metadata']['file_size'],
                    'is_signed': analysis_result['metadata']['is_signed'],
                    'is_debuggable': analysis_result['metadata']['is_debuggable'],
                    'uses_native_code': analysis_result['metadata']['uses_native_code'],
                    
                    # Permission analysis
                    'permissions': analysis_result['permissions']['permissions'],
                    'suspicious_permissions': analysis_result['permissions']['suspicious_permissions'],
                    'permission_count': analysis_result['permissions']['total_count'],
                    'critical_permissions': analysis_result['permissions']['permission_categories']['critical'],
                    'high_risk_permissions': analysis_result['permissions']['permission_categories']['high'],
                    
                    # Certificate analysis
                    'certificates': analysis_result['certificates']['certificates'],
                    'certificate_count': analysis_result['certificates']['certificate_count'],
                    'has_valid_certificates': analysis_result['certificates']['has_valid_certificates'],
                    'has_self_signed': analysis_result['certificates']['has_self_signed'],
                    
                    # API and URL analysis
                    'suspicious_apis': analysis_result['api_calls']['suspicious_apis'],
                    'crypto_apis': analysis_result['api_calls']['crypto_apis'],
                    'network_apis': analysis_result['api_calls']['network_apis'],
                    'telephony_apis': analysis_result['api_calls']['telephony_apis'],
                    'reflection_apis': analysis_result['api_calls']['reflection_apis'],
                    'total_methods': analysis_result['api_calls']['total_methods'],
                    
                    'http_urls': analysis_result['urls']['http_urls'],
                    'https_urls': analysis_result['urls']['https_urls'],
                    'suspicious_urls': analysis_result['urls']['suspicious_urls'],
                    'ip_addresses': analysis_result['urls']['ip_addresses'],
                    
                    # ML prediction results
                    'ml_prediction': analysis_result.get('ml_prediction', {}),
                    'is_suspicious': analysis_result['security_analysis']['is_suspicious'],
                    'security_analysis': analysis_result['security_analysis'],
                    'ml_analysis': analysis_result.get('ml_analysis', {}),
                    'dynamic_analysis': analysis_result.get('dynamic_analysis', {}),
                    'recommendations': analysis_result['security_analysis'].get('recommendations', [])
                }
            }
            
            return jsonify(response_data)
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    """Scan APK from URL"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
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
    """Get enhanced analysis history"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT filename, package_name, app_name, risk_score, is_suspicious, timestamp, analysis_data
            FROM apk_analysis
            ORDER BY timestamp DESC
            LIMIT 50
        ''')
        
        results = []
        for row in cursor.fetchall():
            try:
                analysis_data = json.loads(row[6]) if row[6] else {}
                results.append({
                    'filename': row[0],
                    'package_name': row[1],
                    'app_name': row[2],
                    'risk_score': row[3],
                    'is_suspicious': bool(row[4]),
                    'timestamp': row[5],
                    'certificate_issues': analysis_data.get('certificates', {}).get('has_self_signed', False),
                    'suspicious_api_count': len(analysis_data.get('api_calls', {}).get('suspicious_apis', [])),
                    'permission_count': analysis_data.get('permissions', {}).get('total_count', 0)
                })
            except:
                # Fallback for old data format
                results.append({
                    'filename': row[0],
                    'package_name': row[1],
                    'app_name': row[2],
                    'risk_score': row[3],
                    'is_suspicious': bool(row[4]),
                    'timestamp': row[5],
                    'certificate_issues': False,
                    'suspicious_api_count': 0,
                    'permission_count': 0
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
    """Get enhanced system statistics"""
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
        
        # Recent threat trends (last 7 days)
        cursor.execute('''
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM apk_analysis 
            WHERE is_suspicious = 1 AND datetime(timestamp) >= datetime('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        ''')
        
        threat_trends = [{'date': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'status': 'success',
            'statistics': {
                'total_analyses': total_analyses,
                'suspicious_count': suspicious_count,
                'legitimate_count': total_analyses - suspicious_count,
                'detection_rate': round((suspicious_count / max(total_analyses, 1)) * 100, 2),
                'risk_distribution': risk_distribution,
                'threat_trends': threat_trends
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def store_enhanced_analysis_result(filename, analysis_result):
    """Store enhanced analysis result in database"""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO apk_analysis 
            (filename, package_name, app_name, file_hash, risk_score, is_suspicious, analysis_data, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            filename,
            analysis_result.get('metadata', {}).get('package_name'),
            analysis_result.get('metadata', {}).get('app_name'),
            analysis_result.get('file_hash'),
            analysis_result.get('security_analysis', {}).get('risk_score'),
            analysis_result.get('security_analysis', {}).get('is_suspicious'),
            json.dumps(analysis_result),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        print(f"Error storing enhanced analysis result: {e}")

def analyze_url(url):
    """Enhanced URL analysis"""
    suspicious_domains = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
        'ngrok.io', 'serveo.net', 'apkpure.com',
        'apkmirror.com', 'apkmonk.com', 'uptodown.com'
    ]
    
    legitimate_domains = [
        'play.google.com', 'apps.apple.com', 'samsung.com',
        'chase.com', 'bankofamerica.com', 'wellsfargo.com',
        'citibank.com', 'jpmorgan.com', 'usbank.com'
    ]
    
    risk_score = 0
    risk_factors = []
    
    # Domain analysis
    for sus_domain in suspicious_domains:
        if sus_domain in url.lower():
            risk_score += 40
            risk_factors.append(f'Suspicious domain: {sus_domain}')
    
    is_legitimate = any(legit_domain in url.lower() for legit_domain in legitimate_domains)
    
    if is_legitimate:
        risk_score = max(0, risk_score - 30)
        risk_factors.append('Legitimate domain detected')
    
    # Protocol analysis
    if not url.startswith('https://'):
        risk_score += 20
        risk_factors.append('Non-HTTPS URL')
    
    # URL structure analysis
    if len(url) > 200:
        risk_score += 10
        risk_factors.append('Unusually long URL')
    
    if url.count('/') > 6:
        risk_score += 10
        risk_factors.append('Complex URL structure')
    
    return {
        'url': url,
        'risk_score': min(risk_score, 100),
        'is_suspicious': risk_score >= 50,
        'risk_level': get_risk_level(risk_score),
        'risk_factors': risk_factors,
        'is_legitimate_source': is_legitimate,
        'analysis_timestamp': datetime.now().isoformat()
    }

def get_risk_level(risk_score):
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

if __name__ == '__main__':
    print("Starting Enhanced Fake Banking APK Detection Backend API...")
    print("Features: Real APK Analysis, Certificate Validation, API Extraction")
    print("API will be available at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
