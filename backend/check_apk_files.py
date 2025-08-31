"""
Check APK file validity in the banking directory
"""
import os
import zipfile

def check_apk_files():
    banking_dir = os.path.join(os.path.dirname(__file__), "mp_police_datasets", "legitimate", "banking")
    
    if not os.path.exists(banking_dir):
        print(f"Directory not found: {banking_dir}")
        return
    
    apk_files = [f for f in os.listdir(banking_dir) if f.endswith('.apk')]
    print(f"Found {len(apk_files)} APK files:")
    print("=" * 60)
    
    valid_files = []
    invalid_files = []
    
    for filename in apk_files:
        apk_path = os.path.join(banking_dir, filename)
        file_size = os.path.getsize(apk_path) / (1024 * 1024)  # MB
        
        try:
            is_valid = zipfile.is_zipfile(apk_path)
            status = "VALID" if is_valid else "INVALID"
            
            if is_valid:
                valid_files.append(filename)
            else:
                invalid_files.append(filename)
                
            print(f"{status:8} | {filename:35} | {file_size:6.1f} MB")
            
        except Exception as e:
            print(f"ERROR    | {filename:35} | {file_size:6.1f} MB | {str(e)}")
            invalid_files.append(filename)
    
    print("=" * 60)
    print(f"Summary: {len(valid_files)} valid, {len(invalid_files)} invalid")
    
    if valid_files:
        print(f"\nValid APK files ({len(valid_files)}):")
        for f in valid_files:
            print(f"  - {f}")
    
    if invalid_files:
        print(f"\nInvalid APK files ({len(invalid_files)}):")
        for f in invalid_files:
            print(f"  - {f}")
    
    return valid_files, invalid_files

if __name__ == "__main__":
    check_apk_files()
