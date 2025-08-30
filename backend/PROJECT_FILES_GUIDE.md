# 🎯 Your Banking APK Detection Project - Essential Files Only

## 📁 **CORE FILES YOU NEED** (Keep These)

### **Main Application**
- **`enhanced_app.py`** - Your main web server (Flask API)
  - Upload APK files via web interface
  - Returns analysis results with ML predictions

### **Analysis Engine**
- **`apk_analyzer.py`** - Analyzes APK files (static analysis)
  - Extracts permissions, certificates, API calls
  - Security risk scoring

### **Machine Learning**
- **`ml_trainer.py`** - ML model training and predictions
  - Trains models to detect malware
  - Makes predictions on new APKs

### **Testing**
- **`test_real_apks.py`** - Test with real APK files
  - Interactive testing script
  - Batch analysis of multiple APKs

### **Advanced Features** (Optional)
- **`dynamic_analyzer.py`** - Runtime behavior analysis
- **`sandbox_manager.py`** - Sandbox environment management  
- **`behavior_monitor.py`** - Real-time monitoring

### **Configuration**
- **`requirements.txt`** - Python dependencies
- **`install_dependencies.bat/.sh`** - Installation scripts

---

## 🗑️ **FILES DELETED** (Were Unnecessary)

- ❌ `app.py` - Old version of web server
- ❌ `simple_app.py` - Basic version  
- ❌ `ml_integration.py` - Duplicate ML code
- ❌ `quick_test.py` - Test script
- ❌ `simple_test.py` - Test script
- ❌ `test_model.py` - Test script
- ❌ `train_models.py` - Duplicate training code

---

## 🚀 **HOW TO USE YOUR PROJECT**

### **Option 1: Web Interface**
```bash
cd backend
python enhanced_app.py
# Open browser: http://localhost:5000
# Upload APK files and see results
```

### **Option 2: Command Line Testing**
```bash
cd backend  
python test_real_apks.py
# Interactive menu to test APK files
```

---

## 📊 **Your Project Structure Now**

```
backend/
├── enhanced_app.py          ← Main web server
├── apk_analyzer.py          ← APK analysis engine
├── ml_trainer.py            ← Machine learning
├── test_real_apks.py        ← Testing script
├── dynamic_analyzer.py      ← Advanced features
├── sandbox_manager.py       ← Advanced features  
├── behavior_monitor.py      ← Advanced features
├── requirements.txt         ← Dependencies
└── models/                  ← Trained ML models
```

**That's it! Only 4 main files you need to focus on.**
