"""
Test the complete Banking APK Detection System
Tests both backend API and frontend integration
"""

import requests
import json
import os
import time

def test_backend_health():
    """Test if backend is running"""
    try:
        response = requests.get('http://localhost:5000/api/health', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✅ Backend Health Check:")
            print(f"   Status: {data.get('status')}")
            print(f"   Version: {data.get('version')}")
            print(f"   Features: {', '.join(data.get('features', []))}")
            return True
        else:
            print(f"❌ Backend health check failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to backend: {e}")
        return False

def test_apk_analysis():
    """Test APK analysis with a sample banking APK"""
    banking_dir = "mp_police_datasets/legitimate/banking"
    
    # Find first APK file
    apk_file = None
    for filename in os.listdir(banking_dir):
        if filename.endswith('.apk'):
            apk_file = os.path.join(banking_dir, filename)
            break
    
    if not apk_file:
        print("❌ No APK files found for testing")
        return False
    
    print(f"🧪 Testing APK Analysis with: {os.path.basename(apk_file)}")
    
    try:
        with open(apk_file, 'rb') as f:
            files = {'file': (os.path.basename(apk_file), f, 'application/vnd.android.package-archive')}
            response = requests.post('http://localhost:5000/api/analyze', files=files, timeout=60)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ APK Analysis Successful:")
            analysis = data.get('analysis', {})
            print(f"   Package: {analysis.get('package_name')}")
            print(f"   App Name: {analysis.get('app_name')}")
            print(f"   Risk Score: {analysis.get('security_analysis', {}).get('risk_score', 'N/A')}")
            print(f"   Suspicious: {analysis.get('is_suspicious', 'N/A')}")
            print(f"   Permissions: {analysis.get('permission_count', 'N/A')}")
            
            # Test ML prediction
            ml_pred = analysis.get('ml_prediction', {})
            if ml_pred:
                print(f"   ML Prediction: {ml_pred.get('prediction', 'N/A')}")
                print(f"   ML Confidence: {ml_pred.get('confidence', 'N/A')}")
            
            return True
        else:
            print(f"❌ APK analysis failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ APK analysis request failed: {e}")
        return False
    except Exception as e:
        print(f"❌ APK analysis error: {e}")
        return False

def test_url_scanning():
    """Test URL scanning functionality"""
    print("🧪 Testing URL Scanning...")
    
    test_urls = [
        "https://play.google.com/store/apps/details?id=com.sbi.lotusintouch",
        "http://suspicious-banking-app.com/download.apk",
        "https://fake-bank-site.net/mobile-app.apk"
    ]
    
    for url in test_urls:
        try:
            data = {'url': url}
            response = requests.post('http://localhost:5000/api/scan-url', 
                                   json=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                analysis = result.get('analysis', {})
                print(f"✅ URL Scan: {url}")
                print(f"   Risk Score: {analysis.get('risk_score', 'N/A')}")
                print(f"   Suspicious: {analysis.get('is_suspicious', 'N/A')}")
                print(f"   Risk Level: {analysis.get('risk_level', 'N/A')}")
            else:
                print(f"❌ URL scan failed for {url}: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ URL scan request failed for {url}: {e}")
    
    return True

def test_statistics():
    """Test statistics endpoint"""
    print("🧪 Testing Statistics...")
    
    try:
        response = requests.get('http://localhost:5000/api/statistics', timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('statistics', {})
            print("✅ Statistics Retrieved:")
            print(f"   Total Analyses: {stats.get('total_analyses', 0)}")
            print(f"   Suspicious Count: {stats.get('suspicious_count', 0)}")
            print(f"   Detection Rate: {stats.get('detection_rate', 0)}%")
            return True
        else:
            print(f"❌ Statistics failed: {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Statistics request failed: {e}")
        return False

def main():
    """Run complete system test"""
    print("🚀 Banking APK Detection System - Complete Test Suite")
    print("=" * 60)
    
    # Test backend connectivity
    if not test_backend_health():
        print("\n❌ Backend is not running. Start with: python enhanced_app.py")
        return
    
    print("\n" + "=" * 60)
    
    # Test APK analysis
    test_apk_analysis()
    
    print("\n" + "=" * 60)
    
    # Test URL scanning
    test_url_scanning()
    
    print("\n" + "=" * 60)
    
    # Test statistics
    test_statistics()
    
    print("\n" + "=" * 60)
    print("🎉 System Test Complete!")
    print("\nNext Steps:")
    print("1. Frontend: http://localhost:3000")
    print("2. Backend API: http://localhost:5000")
    print("3. Upload APK files through web interface")
    print("4. Monitor analysis results and statistics")

if __name__ == "__main__":
    main()
