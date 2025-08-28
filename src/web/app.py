"""
Flask Web Application for APK Analysis
Provides a user-friendly interface for uploading and analyzing APK files
"""

import os
import sys
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import tempfile
import json

# Add src to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from analysis.apk_analyzer import APKAnalyzer
from analysis.dynamic_analyzer import DynamicAnalyzer
from ml.classifier import APKClassifier
from utils.reporter import ReportGenerator

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Configuration
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
ALLOWED_EXTENSIONS = {'apk'}

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

# Initialize components
analyzer = APKAnalyzer()
dynamic_analyzer = DynamicAnalyzer()
classifier = APKClassifier()
reporter = ReportGenerator()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page with upload form"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle APK file upload and analysis"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        
        try:
            # Perform analysis
            analysis_result = analyzer.analyze(filepath)
            
            # Classify APK
            model_path = 'models/banking_apk_classifier.pkl'
            if os.path.exists(model_path):
                classifier.load_model(model_path)
                prediction = classifier.predict(analysis_result.features)
                prediction_dict = {
                    'is_fake': prediction.is_fake,
                    'confidence': prediction.confidence,
                    'probability_fake': prediction.probability_fake,
                    'probability_legitimate': prediction.probability_legitimate,
                    'method': 'ml_model',
                    'model_used': prediction.model_used
                }
            else:
                prediction_dict = classifier.rule_based_classify(analysis_result)
            
            # Generate report
            report = reporter.generate_report(analysis_result, prediction_dict, filepath)
            
            # Save reports
            report_id = Path(filename).stem
            json_report_path = os.path.join(REPORTS_FOLDER, f"{report_id}.json")
            html_report_path = os.path.join(REPORTS_FOLDER, f"{report_id}.html")
            
            reporter.save_report(report, json_report_path)
            reporter.save_html_report(report, html_report_path)
            
            # Clean up uploaded file
            os.remove(filepath)
            
            return render_template('results.html', 
                                 report=report, 
                                 report_id=report_id,
                                 filename=filename)
            
        except Exception as e:
            flash(f'Analysis failed: {str(e)}')
            if os.path.exists(filepath):
                os.remove(filepath)
            return redirect(url_for('index'))
    
    flash('Invalid file type. Please upload an APK file.')
    return redirect(url_for('index'))

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for APK analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        # Save temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
            file.save(tmp_file.name)
            
            # Analyze APK
            analysis_result = analyzer.analyze(tmp_file.name)
            
            # Classify
            model_path = 'models/banking_apk_classifier.pkl'
            if os.path.exists(model_path):
                classifier.load_model(model_path)
                prediction = classifier.predict(analysis_result.features)
                prediction_dict = {
                    'is_fake': prediction.is_fake,
                    'confidence': prediction.confidence,
                    'probability_fake': prediction.probability_fake,
                    'probability_legitimate': prediction.probability_legitimate,
                    'method': 'ml_model'
                }
            else:
                prediction_dict = classifier.rule_based_classify(analysis_result)
            
            # Generate report
            report = reporter.generate_report(analysis_result, prediction_dict, file.filename)
            
            # Clean up
            os.unlink(tmp_file.name)
            
            return jsonify(report)
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/report/<report_id>')
def view_report(report_id):
    """View HTML report"""
    html_report_path = os.path.join(REPORTS_FOLDER, f"{report_id}.html")
    if os.path.exists(html_report_path):
        return send_file(html_report_path)
    else:
        flash('Report not found')
        return redirect(url_for('index'))

@app.route('/download/<report_id>')
def download_report(report_id):
    """Download JSON report"""
    json_report_path = os.path.join(REPORTS_FOLDER, f"{report_id}.json")
    if os.path.exists(json_report_path):
        return send_file(json_report_path, as_attachment=True)
    else:
        flash('Report not found')
        return redirect(url_for('index'))

@app.route('/train_model')
def train_model():
    """Train a new model with synthetic data"""
    try:
        results = classifier.train_and_save_demo_model()
        return jsonify({
            'status': 'success',
            'message': 'Model trained successfully',
            'results': results
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'components': {
            'analyzer': 'ready',
            'classifier': 'ready' if classifier.is_trained else 'not_trained',
            'reporter': 'ready'
        }
    })

if __name__ == '__main__':
    # Train model if it doesn't exist
    model_path = 'models/banking_apk_classifier.pkl'
    if not os.path.exists(model_path):
        print("Training initial model...")
        try:
            classifier.train_and_save_demo_model(model_path)
            print("Model training completed!")
        except Exception as e:
            print(f"Model training failed: {e}")
    
    print("Starting Fake Banking APK Detection System...")
    print("Access the web interface at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
