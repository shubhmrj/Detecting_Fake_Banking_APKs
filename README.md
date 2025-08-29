# Fake Banking APK Detection System

A comprehensive system for detecting and analyzing fake banking APKs using machine learning and static analysis techniques.

## 🏗️ Clean Project Structure

```
fake-apk-detection/
├── backend/                    # Flask API Backend
│   ├── app.py                 # Main Flask application
│   ├── requirements.txt       # Backend dependencies
│   └── Dockerfile            # Backend container
├── frontend/                  # Modern Web Frontend
│   ├── index.html            # Main HTML page
│   ├── app.js                # Frontend JavaScript
│   ├── styles.css            # Custom styles
│   ├── package.json          # Frontend dependencies
│   ├── Dockerfile            # Frontend container
│   └── nginx.conf            # Nginx configuration
├── docker-compose.yml        # Multi-container setup
├── .gitignore               # Git ignore rules
└── README.md                # Documentation
```

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
# Start both frontend and backend
docker-compose up -d

# Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:5000
```

### Option 2: Manual Setup

#### Backend Setup
```bash
cd backend
pip install -r requirements.txt
python app.py
```

#### Frontend Setup
```bash
cd frontend
# Serve with Python (simple)
python -m http.server 3000

# Or use any web server
python src/web/app.py
```

## Key Components

1. **APK Parser**: Extracts metadata, permissions, and certificates
2. **Feature Extractor**: Converts APK attributes to ML features
3. **Classifier**: ML model for authenticity detection
4. **Reporter**: Generates detailed analysis reports

## Technologies

- Python 3.8+
- scikit-learn, pandas, numpy
- Flask (web interface)
- androguard (APK analysis)
- cryptography (certificate validation)
