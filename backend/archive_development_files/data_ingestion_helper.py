"""
Banking APK Data Ingestion Helper
Easy system to add new banking APK data and retrain the model
"""

import os
import shutil
import zipfile
from datetime import datetime
from train_banking_model_alternative import AlternativeBankingAPKTrainer

class BankingDataIngestionHelper:
    def __init__(self):
        self.legitimate_dir = os.path.join("mp_police_datasets", "legitimate", "banking")
        self.malicious_dir = os.path.join("mp_police_datasets", "malicious")
        self.trainer = AlternativeBankingAPKTrainer()
        
        # Ensure directories exist
        os.makedirs(self.legitimate_dir, exist_ok=True)
        os.makedirs(self.malicious_dir, exist_ok=True)
    
    def add_legitimate_banking_apks(self, apk_folder_path):
        """
        Add legitimate banking APKs from a folder
        
        Args:
            apk_folder_path (str): Path to folder containing legitimate banking APKs
        """
        print(f"Adding legitimate banking APKs from: {apk_folder_path}")
        print("=" * 60)
        
        if not os.path.exists(apk_folder_path):
            print(f"ERROR: Folder not found: {apk_folder_path}")
            return False
        
        apk_files = [f for f in os.listdir(apk_folder_path) if f.endswith('.apk')]
        
        if not apk_files:
            print(f"ERROR: No APK files found in {apk_folder_path}")
            return False
        
        print(f"Found {len(apk_files)} APK files")
        
        valid_count = 0
        invalid_count = 0
        
        for apk_file in apk_files:
            source_path = os.path.join(apk_folder_path, apk_file)
            dest_path = os.path.join(self.legitimate_dir, apk_file)
            
            # Validate APK file
            if zipfile.is_zipfile(source_path):
                try:
                    shutil.copy2(source_path, dest_path)
                    print(f"✓ Added: {apk_file}")
                    valid_count += 1
                except Exception as e:
                    print(f"✗ Error copying {apk_file}: {str(e)}")
                    invalid_count += 1
            else:
                print(f"✗ Invalid APK: {apk_file} (corrupted or wrong format)")
                invalid_count += 1
        
        print(f"\nSummary:")
        print(f"  Valid APKs added: {valid_count}")
        print(f"  Invalid/Failed: {invalid_count}")
        print(f"  Total legitimate APKs now: {self.count_legitimate_apks()}")
        
        return valid_count > 0
    
    def add_malicious_apks(self, apk_folder_path):
        """
        Add malicious APKs from a folder
        
        Args:
            apk_folder_path (str): Path to folder containing malicious APKs
        """
        print(f"Adding malicious APKs from: {apk_folder_path}")
        print("=" * 60)
        
        if not os.path.exists(apk_folder_path):
            print(f"ERROR: Folder not found: {apk_folder_path}")
            return False
        
        apk_files = [f for f in os.listdir(apk_folder_path) if f.endswith('.apk')]
        
        if not apk_files:
            print(f"ERROR: No APK files found in {apk_folder_path}")
            return False
        
        print(f"Found {len(apk_files)} APK files")
        
        valid_count = 0
        invalid_count = 0
        
        for apk_file in apk_files:
            source_path = os.path.join(apk_folder_path, apk_file)
            dest_path = os.path.join(self.malicious_dir, apk_file)
            
            # Validate APK file
            if zipfile.is_zipfile(source_path):
                try:
                    shutil.copy2(source_path, dest_path)
                    print(f"✓ Added: {apk_file}")
                    valid_count += 1
                except Exception as e:
                    print(f"✗ Error copying {apk_file}: {str(e)}")
                    invalid_count += 1
            else:
                print(f"✗ Invalid APK: {apk_file} (corrupted or wrong format)")
                invalid_count += 1
        
        print(f"\nSummary:")
        print(f"  Valid APKs added: {valid_count}")
        print(f"  Invalid/Failed: {invalid_count}")
        print(f"  Total malicious APKs now: {self.count_malicious_apks()}")
        
        return valid_count > 0
    
    def count_legitimate_apks(self):
        """Count valid legitimate APKs"""
        if not os.path.exists(self.legitimate_dir):
            return 0
        
        apk_files = [f for f in os.listdir(self.legitimate_dir) if f.endswith('.apk')]
        valid_count = 0
        
        for apk_file in apk_files:
            apk_path = os.path.join(self.legitimate_dir, apk_file)
            if zipfile.is_zipfile(apk_path):
                valid_count += 1
        
        return valid_count
    
    def count_malicious_apks(self):
        """Count valid malicious APKs"""
        if not os.path.exists(self.malicious_dir):
            return 0
        
        apk_files = [f for f in os.listdir(self.malicious_dir) if f.endswith('.apk')]
        valid_count = 0
        
        for apk_file in apk_files:
            apk_path = os.path.join(self.malicious_dir, apk_file)
            if zipfile.is_zipfile(apk_path):
                valid_count += 1
        
        return valid_count
    
    def get_dataset_status(self):
        """Get current dataset status"""
        legitimate_count = self.count_legitimate_apks()
        malicious_count = self.count_malicious_apks()
        
        print("Current Dataset Status")
        print("=" * 40)
        print(f"Legitimate Banking APKs: {legitimate_count}")
        print(f"Malicious APKs: {malicious_count}")
        print(f"Total APKs: {legitimate_count + malicious_count}")
        print()
        
        # Model training recommendations
        if legitimate_count >= 5:
            print("[OK] Sufficient legitimate data for robust anomaly detection")
        elif legitimate_count >= 2:
            print("[WARNING] Minimal legitimate data - consider adding more samples")
        else:
            print("[ERROR] Insufficient legitimate data for training")
        
        if malicious_count >= 10:
            print("[OK] Sufficient malicious data for supervised learning")
        elif malicious_count >= 1:
            print("[INFO] Some malicious data available - consider supervised approach")
        else:
            print("[INFO] No malicious data - using anomaly detection approach")
        
        return {
            'legitimate_count': legitimate_count,
            'malicious_count': malicious_count,
            'total_count': legitimate_count + malicious_count,
            'can_train_anomaly': legitimate_count >= 2,
            'can_train_supervised': legitimate_count >= 5 and malicious_count >= 10
        }
    
    def retrain_model(self):
        """Retrain the banking detection model with current data"""
        print("Retraining Banking Detection Model")
        print("=" * 50)
        
        status = self.get_dataset_status()
        
        if not status['can_train_anomaly']:
            print("ERROR: Insufficient data for training")
            print("Need at least 2 legitimate banking APKs")
            return False
        
        # Train using alternative approach (works without androguard issues)
        print("Training using alternative approach...")
        
        if self.trainer.train_anomaly_detection_model():
            self.trainer.save_model()
            print("\n✓ Model retraining completed successfully!")
            print("✓ New model saved to models/ directory")
            print("✓ Flask API will automatically load the new model")
            return True
        else:
            print("\n✗ Model retraining failed!")
            return False
    
    def interactive_data_addition(self):
        """Interactive mode for adding data"""
        print("Banking APK Data Ingestion - Interactive Mode")
        print("=" * 60)
        
        while True:
            print("\nOptions:")
            print("1. Add legitimate banking APKs from folder")
            print("2. Add malicious APKs from folder") 
            print("3. View dataset status")
            print("4. Retrain model")
            print("5. Exit")
            
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                folder_path = input("Enter path to folder with legitimate banking APKs: ").strip()
                if folder_path:
                    self.add_legitimate_banking_apks(folder_path)
            
            elif choice == '2':
                folder_path = input("Enter path to folder with malicious APKs: ").strip()
                if folder_path:
                    self.add_malicious_apks(folder_path)
            
            elif choice == '3':
                self.get_dataset_status()
            
            elif choice == '4':
                self.retrain_model()
            
            elif choice == '5':
                print("Exiting...")
                break
            
            else:
                print("Invalid choice. Please enter 1-5.")

def main():
    """Main function for command line usage"""
    import sys
    
    helper = BankingDataIngestionHelper()
    
    if len(sys.argv) < 2:
        # Interactive mode
        helper.interactive_data_addition()
    else:
        command = sys.argv[1].lower()
        
        if command == 'status':
            helper.get_dataset_status()
        
        elif command == 'retrain':
            helper.retrain_model()
        
        elif command == 'add-legitimate' and len(sys.argv) >= 3:
            folder_path = sys.argv[2]
            helper.add_legitimate_banking_apks(folder_path)
        
        elif command == 'add-malicious' and len(sys.argv) >= 3:
            folder_path = sys.argv[2]
            helper.add_malicious_apks(folder_path)
        
        else:
            print("Usage:")
            print("  python data_ingestion_helper.py                    # Interactive mode")
            print("  python data_ingestion_helper.py status             # Show dataset status")
            print("  python data_ingestion_helper.py retrain            # Retrain model")
            print("  python data_ingestion_helper.py add-legitimate <folder>  # Add legitimate APKs")
            print("  python data_ingestion_helper.py add-malicious <folder>   # Add malicious APKs")

if __name__ == "__main__":
    main()
