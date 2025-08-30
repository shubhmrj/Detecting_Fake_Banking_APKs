"""
MP Police Banking APK Data Collector
Automated collection of legitimate and malicious APK datasets for training
"""

import os
import requests
import json
import hashlib
from pathlib import Path
import time
from urllib.parse import urlparse
import sqlite3
from datetime import datetime

class MPPoliceDataCollector:
    def __init__(self):
        self.base_dir = "mp_police_datasets"
        self.setup_directories()
        self.setup_database()
        
    def setup_directories(self):
        """Create directory structure for MP Police datasets"""
        directories = [
            f"{self.base_dir}/legitimate/banking",
            f"{self.base_dir}/legitimate/payment", 
            f"{self.base_dir}/malicious/drebin",
            f"{self.base_dir}/malicious/cicmaldroid",
            f"{self.base_dir}/malicious/andmal2020",
            f"{self.base_dir}/malicious/malradar",
            f"{self.base_dir}/malicious/virusshare",
            f"{self.base_dir}/test_samples",
            f"{self.base_dir}/signatures",
            f"{self.base_dir}/metadata"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
        print("✅ Directory structure created for MP Police datasets")
    
    def setup_database(self):
        """Setup SQLite database for tracking APK signatures and metadata"""
        db_path = f"{self.base_dir}/apk_database.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # APK metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS apk_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                package_name TEXT,
                app_name TEXT,
                version_name TEXT,
                version_code INTEGER,
                file_hash TEXT UNIQUE,
                file_size INTEGER,
                is_legitimate BOOLEAN,
                source TEXT,
                download_date TEXT,
                certificate_hash TEXT,
                permissions TEXT,
                analysis_status TEXT DEFAULT 'pending'
            )
        ''')
        
        # Banking app whitelist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS banking_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bank_name TEXT NOT NULL,
                package_name TEXT UNIQUE,
                certificate_hash TEXT,
                official_source TEXT,
                verified_date TEXT,
                is_active BOOLEAN DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized for APK tracking")
    
    def get_indian_banking_apps(self):
        """List of major Indian banking apps to collect"""
        return {
            # Major Indian Banks
            "State Bank of India": "com.sbi.lotza.newmobilebanking",
            "HDFC Bank": "com.snapwork.hdfc",
            "ICICI Bank": "com.csam.icici.bank.imobile",
            "Axis Bank": "com.axis.mobile",
            "Punjab National Bank": "com.pnb.onlite",
            "Bank of Baroda": "com.baroda.barobank",
            "Canara Bank": "com.canara.canaramobile",
            "Union Bank": "com.unionbank.ebanking",
            "Indian Bank": "com.indianbank.indianbankmobile",
            "Central Bank": "com.centralbank.cbsmobile",
            
            # Payment Apps
            "Paytm": "net.one97.paytm",
            "PhonePe": "com.phonepe.app",
            "Google Pay": "com.google.android.apps.nbu.paisa.user",
            "Amazon Pay": "in.amazon.mShop.android.shopping",
            "BHIM UPI": "in.org.npci.upiapp",
            
            # Digital Wallets
            "MobiKwik": "com.mobikwik_new",
            "FreeCharge": "com.freecharge.android",
            "Airtel Money": "com.myairtelapp",
            "Jio Money": "com.ril.jio.jiopay"
        }
    
    def create_banking_whitelist(self):
        """Create whitelist database of legitimate banking apps"""
        banking_apps = self.get_indian_banking_apps()
        
        conn = sqlite3.connect(f"{self.base_dir}/apk_database.db")
        cursor = conn.cursor()
        
        for bank_name, package_name in banking_apps.items():
            cursor.execute('''
                INSERT OR REPLACE INTO banking_whitelist 
                (bank_name, package_name, official_source, verified_date)
                VALUES (?, ?, ?, ?)
            ''', (bank_name, package_name, "Google Play Store", datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Banking whitelist created with {len(banking_apps)} legitimate apps")
        return banking_apps
    
    def download_apk_from_apkmirror(self, package_name, app_name):
        """
        Instructions for downloading APKs from APKMirror
        (Manual process due to anti-bot protection)
        """
        apkmirror_url = f"https://www.apkmirror.com/?s={package_name}"
        
        instructions = f"""
        📱 Manual Download Instructions for {app_name}:
        
        1. Visit: {apkmirror_url}
        2. Find the latest version of {app_name}
        3. Download the APK file
        4. Save to: {self.base_dir}/legitimate/banking/{package_name}.apk
        5. Run: python mp_police_data_collector.py --verify {package_name}
        
        ⚠️  APKMirror has anti-bot protection, manual download required
        """
        
        return instructions
    
    def get_malware_dataset_links(self):
        """Provide links and instructions for downloading malware datasets"""
        datasets = {
            "Drebin": {
                "url": "https://www.sec.cs.tu-bs.de/~danarp/drebin/",
                "description": "Academic malware dataset with 5,560 malware samples",
                "access": "Request access via email to researchers",
                "target_dir": f"{self.base_dir}/malicious/drebin/"
            },
            
            "CCCS-CIC-AndMal-2020": {
                "url": "https://www.unb.ca/cic/datasets/andmal2020.html",
                "description": "Canadian Institute dataset with 200K+ samples",
                "access": "Direct download available",
                "target_dir": f"{self.base_dir}/malicious/andmal2020/"
            },
            
            "CICMalDroid2020": {
                "url": "https://www.unb.ca/cic/datasets/maldroid2020.html", 
                "description": "Android malware dataset with detailed features",
                "access": "Direct download available",
                "target_dir": f"{self.base_dir}/malicious/cicmaldroid/"
            },
            
            "MalRadar": {
                "url": "https://malradar.com/",
                "description": "Real-time malware detection dataset",
                "access": "Request access via registration",
                "target_dir": f"{self.base_dir}/malicious/malradar/"
            },
            
            "VirusShare": {
                "url": "https://virusshare.com/",
                "description": "Large malware sample repository",
                "access": "Registration required for download",
                "target_dir": f"{self.base_dir}/malicious/virusshare/"
            },
            
            "MalwareBazaar": {
                "url": "https://bazaar.abuse.ch/",
                "description": "Real-time malware samples",
                "access": "API available for automated download",
                "target_dir": f"{self.base_dir}/malicious/bazaar/"
            }
        }
        
        return datasets
    
    def download_malwarebazaar_samples(self, max_samples=100):
        """Download recent Android malware samples from MalwareBazaar API"""
        api_url = "https://mb-api.abuse.ch/api/v1/"
        
        # Query for recent Android malware
        payload = {
            "query": "get_recent",
            "selector": "time"
        }
        
        try:
            response = requests.post(api_url, data=payload, timeout=30)
            data = response.json()
            
            if data.get("query_status") == "ok":
                samples = data.get("data", [])
                android_samples = [s for s in samples if "android" in s.get("file_type", "").lower()][:max_samples]
                
                print(f"📥 Found {len(android_samples)} Android malware samples")
                
                download_dir = f"{self.base_dir}/malicious/bazaar/"
                os.makedirs(download_dir, exist_ok=True)
                
                for sample in android_samples:
                    sha256 = sample.get("sha256_hash")
                    if sha256:
                        # Download sample
                        download_payload = {"query": "get_file", "sha256_hash": sha256}
                        file_response = requests.post(api_url, data=download_payload, timeout=60)
                        
                        if file_response.status_code == 200:
                            file_path = os.path.join(download_dir, f"{sha256}.apk")
                            with open(file_path, 'wb') as f:
                                f.write(file_response.content)
                            print(f"✅ Downloaded: {sha256}.apk")
                        
                        time.sleep(1)  # Rate limiting
                
                return len(android_samples)
            
        except Exception as e:
            print(f"❌ Error downloading from MalwareBazaar: {e}")
            return 0
    
    def generate_collection_script(self):
        """Generate automated collection script"""
        script_content = f'''#!/bin/bash
# MP Police APK Data Collection Script

echo "🚀 Starting MP Police APK Data Collection"
echo "=========================================="

# Create directories
mkdir -p {self.base_dir}/legitimate/banking
mkdir -p {self.base_dir}/malicious

# Download legitimate banking APKs (manual process)
echo "📱 Step 1: Download Legitimate Banking APKs"
echo "Visit these sources and download APKs:"
echo "• Google Play Store (use APK extraction tools)"
echo "• APKMirror.com (manual download)"
echo "• APKPure.com (alternative source)"

# Download malware datasets
echo "🦠 Step 2: Download Malware Datasets"
echo "Download from these sources:"
echo "• Drebin: https://www.sec.cs.tu-bs.de/~danarp/drebin/"
echo "• AndMal2020: https://www.unb.ca/cic/datasets/andmal2020.html"
echo "• CICMalDroid: https://www.unb.ca/cic/datasets/maldroid2020.html"

# Automated MalwareBazaar download
echo "📥 Step 3: Automated MalwareBazaar Download"
python3 mp_police_data_collector.py --download-bazaar

echo "✅ Data collection setup complete!"
echo "📊 Next: Run training with collected datasets"
'''
        
        script_path = f"{self.base_dir}/collect_data.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        os.chmod(script_path, 0o755)
        print(f"✅ Collection script created: {script_path}")
    
    def create_collection_guide(self):
        """Create comprehensive data collection guide"""
        banking_apps = self.get_indian_banking_apps()
        datasets = self.get_malware_dataset_links()
        
        guide_content = f"""# MP Police Banking APK Data Collection Guide

## 🎯 Objective
Collect comprehensive dataset of legitimate banking APKs and malware samples for MP Police cybercrime detection system.

## 📊 Target Dataset Size
- **Legitimate Banking APKs**: 50-100 samples
- **Malware Samples**: 200-500 samples
- **Total Training Data**: 250-600 labeled samples

## 🏦 Legitimate Banking APKs to Collect

### Major Indian Banks ({len([k for k in banking_apps.keys() if 'Bank' in k])} banks):
"""
        
        for bank, package in banking_apps.items():
            if 'Bank' in bank:
                guide_content += f"- **{bank}**: `{package}`\n"
        
        guide_content += f"""
### Payment & Digital Wallet Apps ({len([k for k in banking_apps.keys() if 'Bank' not in k])} apps):
"""
        
        for app, package in banking_apps.items():
            if 'Bank' not in app:
                guide_content += f"- **{app}**: `{package}`\n"
        
        guide_content += """
## 📥 Collection Sources

### Legitimate APKs:
1. **Google Play Store** (Primary source)
   - Use APK extraction tools (APK Extractor, ML Manager)
   - Verify digital signatures
   
2. **APKMirror.com** (Backup source)
   - Manual download required (anti-bot protection)
   - Verify checksums against Play Store
   
3. **APKPure.com** (Alternative source)
   - Additional verification recommended

### Malware Datasets:
"""
        
        for name, info in datasets.items():
            guide_content += f"""
#### {name}
- **URL**: {info['url']}
- **Description**: {info['description']}
- **Access**: {info['access']}
- **Target Directory**: `{info['target_dir']}`
"""
        
        guide_content += """
## 🚀 Collection Process

### Step 1: Setup Environment
```bash
cd backend
python mp_police_data_collector.py --setup
```

### Step 2: Create Banking Whitelist
```bash
python mp_police_data_collector.py --create-whitelist
```

### Step 3: Download Legitimate APKs
```bash
# Manual process - follow instructions for each app
python mp_police_data_collector.py --download-legitimate
```

### Step 4: Download Malware Samples
```bash
# Automated download from MalwareBazaar
python mp_police_data_collector.py --download-bazaar

# Manual downloads from academic sources
# Follow dataset-specific instructions
```

### Step 5: Verify and Organize Data
```bash
python mp_police_data_collector.py --verify-all
```

## 📊 Expected Timeline
- **Day 1-2**: Setup and legitimate APK collection
- **Day 3-4**: Malware dataset downloads
- **Day 5**: Data verification and organization
- **Day 6-7**: Model training and testing

## 🎯 Success Metrics
- Minimum 50 legitimate banking APKs collected
- Minimum 200 malware samples collected
- All APKs verified and analyzed
- Database populated with metadata
- Ready for ML model training

## 🔄 Next Steps After Collection
1. Run feature extraction on all APKs
2. Train ML models with real data
3. Test model accuracy on validation set
4. Deploy for MP Police cybercrime unit
"""
        
        guide_path = f"{self.base_dir}/MP_POLICE_COLLECTION_GUIDE.md"
        with open(guide_path, 'w') as f:
            f.write(guide_content)
        
        print(f"✅ Collection guide created: {guide_path}")

def main():
    print("🚀 MP Police Banking APK Data Collector")
    print("=" * 50)
    
    collector = MPPoliceDataCollector()
    
    # Setup for MP Police project
    collector.create_banking_whitelist()
    collector.generate_collection_script()
    collector.create_collection_guide()
    
    print("\n📋 Next Steps:")
    print("1. Review the collection guide")
    print("2. Start downloading legitimate banking APKs")
    print("3. Download malware datasets")
    print("4. Run training with collected data")
    
    # Show collection status
    datasets = collector.get_malware_dataset_links()
    print(f"\n📊 Dataset Sources Available: {len(datasets)}")
    
    banking_apps = collector.get_indian_banking_apps()
    print(f"🏦 Banking Apps to Collect: {len(banking_apps)}")
    
    print(f"\n💾 Data Directory: {collector.base_dir}/")
    print("📖 Read: MP_POLICE_COLLECTION_GUIDE.md for detailed instructions")

if __name__ == "__main__":
    main()
