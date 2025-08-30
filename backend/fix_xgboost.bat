@echo off
echo Fixing XGBoost version conflict...
echo.

echo Step 1: Removing all XGBoost installations...
pip uninstall xgboost -y
conda uninstall xgboost -y

echo.
echo Step 2: Installing XGBoost via conda-forge...
conda install xgboost -c conda-forge -y

echo.
echo Step 3: Testing XGBoost installation...
python -c "import xgboost; print('XGBoost version:', xgboost.__version__)"

echo.
echo XGBoost fix complete!
pause
