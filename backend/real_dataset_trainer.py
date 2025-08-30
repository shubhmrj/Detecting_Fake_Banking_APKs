"""
Real Dataset Integration for Banking APK Malware Detection
This script helps you integrate real APK datasets to improve model accuracy
"""

import os
import pandas as pd
import json
from pathlib import Path
from ml_trainer import APKMLTrainer
from apk_analyzer import EnhancedAPKAnalyzer

class RealDatasetTrainer:
    def __init__(self):
        self.analyzer = EnhancedAPKAnalyzer()
        self.ml_trainer = APKMLTrainer()
        self.dataset_path = "datasets/"
        os.makedirs(self.dataset_path, exist_ok=True)
        
    def process_apk_directory(self, directory_path, label, max_files=None):
        """
        Process a directory of APK files and extract features
        
        Args:
            directory_path: Path to directory containing APK files
            label: 0 for legitimate, 1 for malicious
            max_files: Maximum number of files to process (None for all)
        """
        apk_files = list(Path(directory_path).glob("*.apk"))
        
        if max_files:
            apk_files = apk_files[:max_files]
        
        print(f"📁 Processing {len(apk_files)} APK files from {directory_path}")
        print(f"🏷️  Label: {'MALICIOUS' if label == 1 else 'LEGITIMATE'}")
        
        processed_data = []
        failed_count = 0
        
        for i, apk_file in enumerate(apk_files, 1):
            try:
                print(f"⚙️  [{i}/{len(apk_files)}] Processing: {apk_file.name}")
                
                # Analyze APK
                features = self.analyzer.analyze_apk(str(apk_file))
                
                # Add label
                features['label'] = label
                features['filename'] = apk_file.name
                
                processed_data.append(features)
                
            except Exception as e:
                print(f"❌ Failed to process {apk_file.name}: {str(e)}")
                failed_count += 1
                continue
        
        print(f"✅ Successfully processed: {len(processed_data)}")
        print(f"❌ Failed: {failed_count}")
        
        return processed_data
    
    def create_training_dataset(self, legitimate_dir, malicious_dir, output_file="real_dataset.json"):
        """
        Create training dataset from legitimate and malicious APK directories
        
        Args:
            legitimate_dir: Directory containing legitimate banking APKs
            malicious_dir: Directory containing malware APKs
            output_file: Output file to save the dataset
        """
        print("🚀 Creating Real APK Training Dataset")
        print("=" * 50)
        
        all_data = []
        
        # Process legitimate APKs
        if os.path.exists(legitimate_dir):
            legitimate_data = self.process_apk_directory(legitimate_dir, label=0)
            all_data.extend(legitimate_data)
        else:
            print(f"⚠️  Legitimate directory not found: {legitimate_dir}")
        
        # Process malicious APKs
        if os.path.exists(malicious_dir):
            malicious_data = self.process_apk_directory(malicious_dir, label=1)
            all_data.extend(malicious_data)
        else:
            print(f"⚠️  Malicious directory not found: {malicious_dir}")
        
        if not all_data:
            print("❌ No data processed. Please check your APK directories.")
            return None
        
        # Save dataset
        output_path = os.path.join(self.dataset_path, output_file)
        with open(output_path, 'w') as f:
            json.dump(all_data, f, indent=2, default=str)
        
        print(f"\n📊 Dataset Summary:")
        print(f"Total samples: {len(all_data)}")
        
        legitimate_count = sum(1 for item in all_data if item['label'] == 0)
        malicious_count = sum(1 for item in all_data if item['label'] == 1)
        
        print(f"✅ Legitimate: {legitimate_count}")
        print(f"🦠 Malicious: {malicious_count}")
        print(f"💾 Saved to: {output_path}")
        
        return all_data
    
    def train_with_real_data(self, dataset_file="real_dataset.json"):
        """Train ML models using real APK dataset"""
        dataset_path = os.path.join(self.dataset_path, dataset_file)
        
        if not os.path.exists(dataset_path):
            print(f"❌ Dataset file not found: {dataset_path}")
            print("Please create dataset first using create_training_dataset()")
            return False
        
        print("🤖 Training ML Models with Real Data")
        print("=" * 40)
        
        # Load dataset
        with open(dataset_path, 'r') as f:
            data = json.load(f)
        
        print(f"📊 Loaded {len(data)} samples")
        
        # Train models
        models = self.ml_trainer.train_models(data)
        
        # Save models
        self.ml_trainer.save_models()
        
        print("✅ Models trained and saved successfully!")
        return True
    
    def evaluate_model_performance(self, test_legitimate_dir, test_malicious_dir):
        """Evaluate model performance on test set"""
        print("📈 Evaluating Model Performance")
        print("=" * 35)
        
        # Load models
        try:
            self.ml_trainer.load_models()
        except:
            print("❌ No trained models found. Please train models first.")
            return
        
        results = []
        
        # Test legitimate APKs
        if os.path.exists(test_legitimate_dir):
            print("Testing legitimate APKs...")
            legit_files = list(Path(test_legitimate_dir).glob("*.apk"))[:10]  # Test 10 files
            
            for apk_file in legit_files:
                try:
                    features = self.analyzer.analyze_apk(str(apk_file))
                    prediction = self.ml_trainer.predict(features)
                    
                    results.append({
                        'file': apk_file.name,
                        'actual': 'legitimate',
                        'predicted': 'malicious' if prediction['prediction'] == 1 else 'legitimate',
                        'confidence': prediction['confidence'],
                        'correct': prediction['prediction'] == 0
                    })
                except Exception as e:
                    print(f"Error testing {apk_file.name}: {e}")
        
        # Test malicious APKs
        if os.path.exists(test_malicious_dir):
            print("Testing malicious APKs...")
            mal_files = list(Path(test_malicious_dir).glob("*.apk"))[:10]  # Test 10 files
            
            for apk_file in mal_files:
                try:
                    features = self.analyzer.analyze_apk(str(apk_file))
                    prediction = self.ml_trainer.predict(features)
                    
                    results.append({
                        'file': apk_file.name,
                        'actual': 'malicious',
                        'predicted': 'malicious' if prediction['prediction'] == 1 else 'legitimate',
                        'confidence': prediction['confidence'],
                        'correct': prediction['prediction'] == 1
                    })
                except Exception as e:
                    print(f"Error testing {apk_file.name}: {e}")
        
        # Calculate accuracy
        if results:
            correct_predictions = sum(1 for r in results if r['correct'])
            accuracy = correct_predictions / len(results)
            
            print(f"\n📊 Performance Results:")
            print(f"Total tested: {len(results)}")
            print(f"Correct predictions: {correct_predictions}")
            print(f"Accuracy: {accuracy:.1%}")
            
            # Show some examples
            print(f"\n🔍 Sample Predictions:")
            for result in results[:5]:
                status = "✅" if result['correct'] else "❌"
                print(f"{status} {result['file']}: {result['predicted']} ({result['confidence']:.1%})")
        
        return results

def main():
    print("🏦 Real Dataset Trainer for Banking APK Detection")
    print("=" * 55)
    
    trainer = RealDatasetTrainer()
    
    print("\n📋 Setup Instructions:")
    print("1. Create directories for your APK files:")
    print("   - datasets/legitimate/  (Put legitimate banking APKs here)")
    print("   - datasets/malicious/   (Put malware APKs here)")
    print("   - datasets/test_legit/  (Test legitimate APKs)")
    print("   - datasets/test_mal/    (Test malicious APKs)")
    
    print("\n2. Download APK datasets:")
    print("   • Legitimate: Official banking apps from Google Play")
    print("   • Malicious: VirusTotal, MalwareBazaar, AndroZoo")
    
    print("\n3. Run training:")
    print("   python real_dataset_trainer.py")
    
    # Interactive menu
    while True:
        print("\n" + "="*50)
        print("Options:")
        print("1. Create training dataset from APK directories")
        print("2. Train models with real data")
        print("3. Evaluate model performance")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            legit_dir = input("Enter legitimate APKs directory [datasets/legitimate]: ").strip() or "datasets/legitimate"
            mal_dir = input("Enter malicious APKs directory [datasets/malicious]: ").strip() or "datasets/malicious"
            
            trainer.create_training_dataset(legit_dir, mal_dir)
        
        elif choice == '2':
            trainer.train_with_real_data()
        
        elif choice == '3':
            test_legit = input("Enter test legitimate APKs directory [datasets/test_legit]: ").strip() or "datasets/test_legit"
            test_mal = input("Enter test malicious APKs directory [datasets/test_mal]: ").strip() or "datasets/test_mal"
            
            trainer.evaluate_model_performance(test_legit, test_mal)
        
        elif choice == '4':
            break
        
        else:
            print("❌ Invalid choice!")

if __name__ == "__main__":
    main()
