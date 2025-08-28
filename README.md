# Fake Banking APK Detection System

An automated system to detect and classify fake banking applications using static and dynamic analysis techniques.

## Features

- **Static Analysis**: Extract APK permissions, signatures, certificates, and metadata
- **Dynamic Analysis**: Monitor network behavior and runtime characteristics
- **Machine Learning**: Classification model to distinguish genuine vs fake banking APKs
- **Web Interface**: Upload and analyze APKs through a user-friendly interface
- **Reporting System**: Flag suspicious APKs with detailed analysis reports

## Architecture

```
├── src/
│   ├── analysis/          # APK analysis modules
│   ├── ml/               # Machine learning components
│   ├── web/              # Web interface
│   └── utils/            # Utility functions
├── data/                 # Sample datasets
├── models/               # Trained ML models
└── reports/              # Analysis reports
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Command Line
```bash
python src/main.py --apk path/to/app.apk
```

### Web Interface
```bash
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
