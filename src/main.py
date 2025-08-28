#!/usr/bin/env python3
"""
Main entry point for the Fake Banking APK Detection System
"""

import argparse
import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent))

from analysis.apk_analyzer import APKAnalyzer
from ml.classifier import APKClassifier
from utils.reporter import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description='Fake Banking APK Detection System')
    parser.add_argument('--apk', required=True, help='Path to APK file to analyze')
    parser.add_argument('--output', default='reports/', help='Output directory for reports')
    parser.add_argument('--model', default='models/banking_apk_classifier.pkl', help='Path to trained model')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.apk):
        print(f"Error: APK file not found: {args.apk}")
        return 1
    
    print(f"Analyzing APK: {args.apk}")
    
    # Initialize components
    analyzer = APKAnalyzer()
    classifier = APKClassifier()
    reporter = ReportGenerator()
    
    try:
        # Step 1: Analyze APK
        print("Step 1: Extracting APK features...")
        analysis_result = analyzer.analyze(args.apk)
        
        # Step 2: Classify
        print("Step 2: Classifying APK...")
        if os.path.exists(args.model):
            classifier.load_model(args.model)
            prediction = classifier.predict(analysis_result.features)
        else:
            print("Warning: No trained model found. Using rule-based classification.")
            prediction = classifier.rule_based_classify(analysis_result)
        
        # Step 3: Generate report
        print("Step 3: Generating report...")
        report = reporter.generate_report(analysis_result, prediction, args.apk)
        
        # Save report
        os.makedirs(args.output, exist_ok=True)
        report_path = os.path.join(args.output, f"analysis_{Path(args.apk).stem}.json")
        reporter.save_report(report, report_path)
        
        print(f"\nAnalysis complete!")
        print(f"Classification: {'FAKE/MALICIOUS' if prediction['is_fake'] else 'LEGITIMATE'}")
        print(f"Confidence: {prediction['confidence']:.2f}")
        print(f"Report saved to: {report_path}")
        
        return 0
        
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
