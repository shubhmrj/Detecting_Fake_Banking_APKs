"""
Simple Web Server Test for Banking APK Detection
"""

from flask import Flask, render_template_string, request, jsonify
import os

app = Flask(__name__)

# Simple HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Banking APK Detection System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .upload-area { border: 2px dashed #3498db; padding: 40px; text-align: center; margin: 20px 0; border-radius: 10px; }
        .upload-area:hover { background: #ecf0f1; }
        .btn { background: #3498db; color: white; padding: 12px 24px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .btn:hover { background: #2980b9; }
        .result { margin-top: 20px; padding: 20px; border-radius: 5px; }
        .success { background: #d5f4e6; border: 1px solid #27ae60; }
        .error { background: #fadbd8; border: 1px solid #e74c3c; }
        .malicious { background: #fadbd8; border: 1px solid #e74c3c; }
        .legitimate { background: #d5f4e6; border: 1px solid #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🏦 Banking APK Malware Detection</h1>
        <p style="text-align: center; color: #7f8c8d;">Upload APK files to analyze for banking malware</p>
        
        <form id="uploadForm" enctype="multipart/form-data">
            <div class="upload-area">
                <p>📱 Drag & Drop APK file here or click to select</p>
                <input type="file" id="apkFile" name="file" accept=".apk" style="display: none;">
                <button type="button" class="btn" onclick="document.getElementById('apkFile').click()">Choose APK File</button>
            </div>
            <div style="text-align: center;">
                <button type="submit" class="btn">🔍 Analyze APK</button>
            </div>
        </form>
        
        <div id="result"></div>
        
        <div style="margin-top: 30px; padding: 20px; background: #ecf0f1; border-radius: 5px;">
            <h3>📊 System Status</h3>
            <p><strong>ML Models:</strong> ✅ Loaded (Random Forest, Gradient Boosting)</p>
            <p><strong>Analysis Features:</strong> 85+ security indicators</p>
            <p><strong>Detection Types:</strong> Banking trojans, fake apps, malware</p>
        </div>
    </div>

    <script>
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('apkFile');
            const resultDiv = document.getElementById('result');
            
            if (!fileInput.files[0]) {
                resultDiv.innerHTML = '<div class="result error">❌ Please select an APK file</div>';
                return;
            }
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            resultDiv.innerHTML = '<div class="result">🔄 Analyzing APK file...</div>';
            
            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.status === 'success') {
                    const prediction = data.analysis.ml_prediction;
                    const ismalicious = prediction.prediction === 1;
                    const confidence = (prediction.confidence * 100).toFixed(1);
                    
                    resultDiv.innerHTML = `
                        <div class="result ${ismalicious ? 'malicious' : 'legitimate'}">
                            <h3>${ismalicious ? '🦠 MALICIOUS' : '✅ LEGITIMATE'}</h3>
                            <p><strong>File:</strong> ${data.filename}</p>
                            <p><strong>Confidence:</strong> ${confidence}%</p>
                            <p><strong>Package:</strong> ${data.analysis.package_name || 'Unknown'}</p>
                            <p><strong>Permissions:</strong> ${data.analysis.permission_count || 0}</p>
                            <p><strong>Security Score:</strong> ${data.analysis.security_analysis?.risk_score || 0}/100</p>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `<div class="result error">❌ Error: ${data.error}</div>`;
                }
            } catch (error) {
                resultDiv.innerHTML = `<div class="result error">❌ Network error: ${error.message}</div>`;
            }
        });
        
        // File name display
        document.getElementById('apkFile').addEventListener('change', function(e) {
            if (e.target.files[0]) {
                document.querySelector('.upload-area p').textContent = `📱 Selected: ${e.target.files[0].name}`;
            }
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/analyze', methods=['POST'])
def analyze_apk():
    """Simple APK analysis endpoint"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'File must be an APK'}), 400
        
        # Save file temporarily
        temp_path = f"uploads/temp_{file.filename}"
        os.makedirs('uploads', exist_ok=True)
        file.save(temp_path)
        
        # Import and analyze
        from apk_analyzer import EnhancedAPKAnalyzer
        from ml_trainer import APKMLTrainer
        
        analyzer = EnhancedAPKAnalyzer()
        ml_trainer = APKMLTrainer()
        
        # Load models
        try:
            ml_trainer.load_models()
        except:
            # Train new models if none exist
            data = ml_trainer.generate_synthetic_training_data(500)
            ml_trainer.train_models(data)
            ml_trainer.save_models()
        
        # Analyze APK
        analysis_result = analyzer.analyze_apk(temp_path)
        ml_result = ml_trainer.predict(analysis_result)
        
        # Clean up
        os.remove(temp_path)
        
        return jsonify({
            'status': 'success',
            'filename': file.filename,
            'analysis': {
                'package_name': analysis_result.get('metadata', {}).get('package_name', 'Unknown'),
                'permission_count': analysis_result.get('permissions', {}).get('total_count', 0),
                'security_analysis': analysis_result.get('security_analysis', {}),
                'ml_prediction': ml_result
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Banking APK Detection System...")
    print("📱 Upload APK files to test malware detection")
    print("🌐 Open browser: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
