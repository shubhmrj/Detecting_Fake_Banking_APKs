#!/bin/bash
echo "Installing APK Analysis System Dependencies..."
echo

echo "Step 1: Installing ML packages via conda (pre-compiled)..."
conda install -y scikit-learn pandas numpy xgboost joblib -c conda-forge

echo
echo "Step 2: Installing remaining packages via pip..."
pip install flask==2.3.3 flask-cors==4.0.0 requests==2.31.0

echo
echo "Step 3: Installing APK analysis packages..."
pip install androguard==3.4.0a1 cryptography==41.0.4

echo
echo "Step 4: Installing dynamic analysis packages..."
pip install docker>=6.0.0 psutil>=5.8.0

echo
echo "Installation complete!"
echo
echo "To test the system:"
echo "1. cd backend"
echo "2. python train_models.py"
echo "3. python enhanced_app.py"
echo
