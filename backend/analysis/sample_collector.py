"""
APK Sample Collection Module
Collects and manages APK samples for analysis and training
"""

import os
import requests
import hashlib
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
import sqlite3
from datetime import datetime
import logging

class APKSampleCollector:
    """Collects and manages APK samples from various sources"""
    
    def __init__(self, storage_dir: str = "data/samples"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database for sample metadata
        self.db_path = self.storage_dir / "samples.db"
        self._init_database()
        
        # Known legitimate banking app sources
        self.legitimate_sources = [
            "https://play.google.com/store/apps/details?id=",
            "https://apps.apple.com/app/",
            # Official bank websites would be added here
        ]
        
        # Known malicious/suspicious sources (for research purposes)
        self.suspicious_sources = [
            # Third-party APK sites, suspicious domains
            "apkpure.com",
            "apkmirror.com",
            "aptoide.com"
        ]
        
        self.logger = self._setup_logging()
    
    def _init_database(self):
        """Initialize SQLite database for sample tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS apk_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT UNIQUE NOT NULL,
                package_name TEXT,
                app_name TEXT,
                version_name TEXT,
                source_url TEXT,
                source_type TEXT,  -- 'legitimate', 'suspicious', 'unknown'
                file_hash TEXT,
                collection_date TEXT,
                analysis_status TEXT DEFAULT 'pending',
                is_banking_app BOOLEAN DEFAULT 0,
                risk_score REAL,
                classification TEXT  -- 'legitimate', 'fake', 'unknown'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS collection_stats (
                date TEXT PRIMARY KEY,
                legitimate_count INTEGER DEFAULT 0,
                suspicious_count INTEGER DEFAULT 0,
                total_analyzed INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _setup_logging(self):
        """Setup logging for sample collection"""
        logger = logging.getLogger('APKSampleCollector')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(self.storage_dir / 'collection.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def collect_from_url(self, url: str, expected_package: str = None) -> Dict[str, Any]:
        """
        Collect APK from a given URL
        """
        try:
            self.logger.info(f"Collecting APK from: {url}")
            
            # Download APK
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            # Generate filename based on URL and timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sample_{timestamp}.apk"
            filepath = self.storage_dir / filename
            
            # Save APK file
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(filepath)
            
            # Determine source type
            source_type = self._classify_source(url)
            
            # Store in database
            self._store_sample_metadata(
                filename=filename,
                source_url=url,
                source_type=source_type,
                file_hash=file_hash
            )
            
            self.logger.info(f"Successfully collected APK: {filename}")
            
            return {
                'status': 'success',
                'filename': filename,
                'filepath': str(filepath),
                'file_hash': file_hash,
                'source_type': source_type
            }
            
        except Exception as e:
            self.logger.error(f"Failed to collect APK from {url}: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def collect_banking_app_samples(self) -> Dict[str, Any]:
        """
        Collect samples of known banking applications
        """
        banking_apps = [
            # Major banking apps (package names for reference)
            "com.chase.sig.android",
            "com.bankofamerica.digitalwallet",
            "com.wellsfargo.mobile.android",
            "com.usaa.mobile.android.usaa",
            "com.citi.citimobile",
            # Add more legitimate banking apps
        ]
        
        results = {
            'collected': 0,
            'failed': 0,
            'samples': []
        }
        
        for package_name in banking_apps:
            # In a real implementation, you would use official sources
            # For demo purposes, we'll simulate collection
            sample_info = self._simulate_banking_app_collection(package_name)
            if sample_info['status'] == 'success':
                results['collected'] += 1
                results['samples'].append(sample_info)
            else:
                results['failed'] += 1
        
        return results
    
    def _simulate_banking_app_collection(self, package_name: str) -> Dict[str, Any]:
        """
        Simulate collection of banking app (for demo purposes)
        """
        # Create a mock entry for demonstration
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"banking_{package_name}_{timestamp}.apk"
        
        # Store metadata
        self._store_sample_metadata(
            filename=filename,
            package_name=package_name,
            source_url=f"https://play.google.com/store/apps/details?id={package_name}",
            source_type='legitimate',
            file_hash=hashlib.md5(filename.encode()).hexdigest()
        )
        
        return {
            'status': 'success',
            'filename': filename,
            'package_name': package_name,
            'source_type': 'legitimate'
        }
    
    def _calculate_file_hash(self, filepath: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _classify_source(self, url: str) -> str:
        """Classify the source of the APK"""
        url_lower = url.lower()
        
        for legit_source in self.legitimate_sources:
            if legit_source.lower() in url_lower:
                return 'legitimate'
        
        for sus_source in self.suspicious_sources:
            if sus_source.lower() in url_lower:
                return 'suspicious'
        
        return 'unknown'
    
    def _store_sample_metadata(self, filename: str, source_url: str = None, 
                              source_type: str = 'unknown', file_hash: str = None,
                              package_name: str = None):
        """Store sample metadata in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO apk_samples 
            (filename, package_name, source_url, source_type, file_hash, collection_date)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (filename, package_name, source_url, source_type, file_hash, 
              datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def get_sample_statistics(self) -> Dict[str, Any]:
        """Get statistics about collected samples"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total samples
        cursor.execute("SELECT COUNT(*) FROM apk_samples")
        total_samples = cursor.fetchone()[0]
        
        # By source type
        cursor.execute("""
            SELECT source_type, COUNT(*) 
            FROM apk_samples 
            GROUP BY source_type
        """)
        by_source = dict(cursor.fetchall())
        
        # By analysis status
        cursor.execute("""
            SELECT analysis_status, COUNT(*) 
            FROM apk_samples 
            GROUP BY analysis_status
        """)
        by_status = dict(cursor.fetchall())
        
        # Banking apps
        cursor.execute("SELECT COUNT(*) FROM apk_samples WHERE is_banking_app = 1")
        banking_apps = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_samples': total_samples,
            'by_source_type': by_source,
            'by_analysis_status': by_status,
            'banking_apps': banking_apps
        }
    
    def get_pending_samples(self) -> List[Dict[str, Any]]:
        """Get list of samples pending analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT filename, package_name, source_url, source_type, file_hash
            FROM apk_samples 
            WHERE analysis_status = 'pending'
            ORDER BY collection_date DESC
        """)
        
        samples = []
        for row in cursor.fetchall():
            samples.append({
                'filename': row[0],
                'package_name': row[1],
                'source_url': row[2],
                'source_type': row[3],
                'file_hash': row[4]
            })
        
        conn.close()
        return samples
    
    def update_analysis_result(self, filename: str, analysis_result: Dict[str, Any]):
        """Update sample with analysis results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE apk_samples 
            SET analysis_status = 'completed',
                package_name = COALESCE(?, package_name),
                app_name = ?,
                version_name = ?,
                risk_score = ?,
                classification = ?,
                is_banking_app = ?
            WHERE filename = ?
        ''', (
            analysis_result.get('package_name'),
            analysis_result.get('app_name'),
            analysis_result.get('version_name'),
            analysis_result.get('risk_score'),
            analysis_result.get('classification'),
            1 if analysis_result.get('is_banking_app', False) else 0,
            filename
        ))
        
        conn.commit()
        conn.close()
    
    def export_training_data(self, output_path: str = None) -> str:
        """Export collected samples as training data"""
        if not output_path:
            output_path = self.storage_dir / "training_data.json"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM apk_samples 
            WHERE analysis_status = 'completed'
            AND classification IS NOT NULL
        """)
        
        columns = [description[0] for description in cursor.description]
        samples = []
        
        for row in cursor.fetchall():
            sample_dict = dict(zip(columns, row))
            samples.append(sample_dict)
        
        conn.close()
        
        # Export to JSON
        with open(output_path, 'w') as f:
            json.dump(samples, f, indent=2)
        
        return str(output_path)
