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
import zipfile
from datetime import datetime
from ml_trainer import APKMLTrainer
from analysis.dynamic_analyzer import DynamicAnalyzer
from train_banking_model import BankingAPKTrainer
from sentinel_banking_detector_windows import SentinelBankingDetector

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
    print("[OK] ML models loaded successfully")
except:
    print("[INFO] Training new ML models...")
    data = ml_trainer.generate_synthetic_training_data(1000)
    ml_trainer.train_models(data)
    ml_trainer.save_models()
    print("[OK] New ML models trained and saved")

# Initialize Banking APK Trainer and Sentinel Detector
banking_trainer = BankingAPKTrainer()
sentinel_detector = SentinelBankingDetector()
print("[OK] Banking detection system initialized")

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
            from analysis.apk_analyzer import APKAnalyzer
            analyzer = APKAnalyzer()
            
            # Perform static analysis
            analysis_result = analyzer.analyze(temp_path)
            
            # Add ML prediction (skip for now as it expects different format)
            # ml_result = ml_trainer.predict(analysis_result)
            # analysis_result['ml_prediction'] = ml_result
            
            # Add banking anomaly detection
            banking_result = sentinel_detector.detect_banking_threat(temp_path)
            analysis_result.banking_detection = banking_result
            
            if not analysis_result:
                return jsonify({
                    'status': 'error',
                    'filename': file.filename,
                    'error': 'APK analysis failed'
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
            
            # Build response with enhanced data using APKAnalysisResult structure
            response_data = {
                'status': 'success',
                'filename': file.filename,
                'analysis': {
                    'package_name': getattr(analysis_result, 'package_name', 'unknown'),
                    'app_name': getattr(analysis_result, 'app_name', 'unknown'),
                    'version_name': getattr(analysis_result, 'version_name', 'unknown'),
                    'version_code': getattr(analysis_result, 'version_code', 0),
                    'file_size': os.path.getsize(temp_path),
                    
                    # Permission analysis
                    'permissions': getattr(analysis_result, 'permissions', []),
                    'suspicious_permissions': getattr(analysis_result, 'suspicious_permissions', []),
                    'permission_count': len(getattr(analysis_result, 'permissions', [])),
                    
                    # Certificate analysis
                    'certificates': getattr(analysis_result, 'certificates', []),
                    'certificate_count': len(getattr(analysis_result, 'certificates', [])),
                    'has_valid_certificates': len(getattr(analysis_result, 'certificates', [])) > 0,
                    
                    # Component analysis
                    'activities': getattr(analysis_result, 'activities', []),
                    'services': getattr(analysis_result, 'services', []),
                    'receivers': getattr(analysis_result, 'receivers', []),
                    
                    # Risk analysis
                    'risk_score': getattr(analysis_result, 'risk_score', 0),
                    'is_suspicious': getattr(analysis_result, 'risk_score', 0) > 50,
                    
                    # Banking anomaly detection
                    'banking_detection': getattr(analysis_result, 'banking_detection', {}),
                    
                    # Features for ML
                    'features': getattr(analysis_result, 'features', {}),
                    
                    # File hashes
                    'file_hashes': getattr(analysis_result, 'file_hashes', {})
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

@app.route('/api/train/legitimate', methods=['POST'])
def train_legitimate():
    """Train model with legitimate banking APK"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'File must be an APK'}), 400
        
        # Save uploaded file to legitimate training directory
        legitimate_dir = os.path.join('mp_police_datasets', 'legitimate', 'banking')
        os.makedirs(legitimate_dir, exist_ok=True)
        
        file_path = os.path.join(legitimate_dir, file.filename)
        file.save(file_path)
        
        # Validate APK file
        if not zipfile.is_zipfile(file_path):
            os.remove(file_path)  # Clean up invalid file
            return jsonify({'error': 'Invalid APK file format'}), 400
        
        # Retrain the banking model
        success = banking_trainer.train_anomaly_detection_model()
        
        if success:
            banking_trainer.save_model()
            # Reload the sentinel detector with new model
            global sentinel_detector
            sentinel_detector = SentinelBankingDetector()
            
            return jsonify({
                'status': 'success',
                'message': f'Legitimate APK {file.filename} added to training set',
                'model_retrained': True
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Model retraining failed'
            }), 500
            
    except Exception as e:
        return jsonify({'error': f'Training failed: {str(e)}'}), 500

@app.route('/api/train/malicious', methods=['POST'])
def train_malicious():
    """Train model with malicious APK (for future supervised learning)"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'File must be an APK'}), 400
        
        # Save uploaded file to malicious training directory
        malicious_dir = os.path.join('mp_police_datasets', 'malicious')
        os.makedirs(malicious_dir, exist_ok=True)
        
        file_path = os.path.join(malicious_dir, file.filename)
        file.save(file_path)
        
        # Validate APK file
        if not zipfile.is_zipfile(file_path):
            os.remove(file_path)  # Clean up invalid file
            return jsonify({'error': 'Invalid APK file format'}), 400
        
        # For now, just store the malicious APK for future supervised learning
        return jsonify({
            'status': 'success',
            'message': f'Malicious APK {file.filename} added to malicious dataset',
            'note': 'Currently using anomaly detection. Supervised learning will be implemented when sufficient malicious samples are collected.'
        })
            
    except Exception as e:
        return jsonify({'error': f'Training failed: {str(e)}'}), 500

@app.route('/api/train/status', methods=['GET'])
def training_status():
    """Get training dataset status"""
    try:
        legitimate_dir = os.path.join('mp_police_datasets', 'legitimate', 'banking')
        malicious_dir = os.path.join('mp_police_datasets', 'malicious')
        
        legitimate_count = 0
        malicious_count = 0
        
        if os.path.exists(legitimate_dir):
            legitimate_files = [f for f in os.listdir(legitimate_dir) if f.endswith('.apk')]
            legitimate_count = len([f for f in legitimate_files if zipfile.is_zipfile(os.path.join(legitimate_dir, f))])
        
        if os.path.exists(malicious_dir):
            malicious_files = [f for f in os.listdir(malicious_dir) if f.endswith('.apk')]
            malicious_count = len([f for f in malicious_files if zipfile.is_zipfile(os.path.join(malicious_dir, f))])
        
        # Check if banking model exists
        model_exists = os.path.exists('models/banking_anomaly_model.pkl')
        
        return jsonify({
            'status': 'success',
            'training_data': {
                'legitimate_samples': legitimate_count,
                'malicious_samples': malicious_count,
                'total_samples': legitimate_count + malicious_count
            },
            'model_status': {
                'banking_model_trained': model_exists,
                'model_type': 'anomaly_detection' if legitimate_count >= 2 else 'insufficient_data',
                'can_train': legitimate_count >= 2
            },
            'recommendations': {
                'min_legitimate_samples': 3,
                'min_malicious_samples': 10,
                'current_approach': 'anomaly_detection',
                'future_approach': 'supervised_learning' if malicious_count >= 10 else 'anomaly_detection'
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Status check failed: {str(e)}'}), 500

@app.route('/api/retrain', methods=['POST'])
def retrain_model():
    """Manually retrain the banking detection model"""
    try:
        # Retrain the banking anomaly detection model
        success = banking_trainer.train_anomaly_detection_model()
        
        if success:
            banking_trainer.save_model()
            # Reload the sentinel detector with new model
            global sentinel_detector
            sentinel_detector = SentinelBankingDetector()
            
            return jsonify({
                'status': 'success',
                'message': 'Banking detection model retrained successfully',
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Model retraining failed - insufficient training data'
            }), 500
            
    except Exception as e:
        return jsonify({'error': f'Retraining failed: {str(e)}'}), 500

if __name__ == '__main__':
    print("[INFO] Starting Enhanced Banking APK Detection API...")
    print("[INFO] Available endpoints:")
    print("  - POST /api/analyze - Analyze APK file")
    print("  - POST /api/train/legitimate - Add legitimate APK to training")
    print("  - POST /api/train/malicious - Add malicious APK to training")
    print("  - GET /api/train/status - Get training status")
    print("  - POST /api/retrain - Manually retrain model")
    print("  - GET /api/health - Health check")
    print("[INFO] Server starting on http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
