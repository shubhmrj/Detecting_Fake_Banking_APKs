#!/usr/bin/env python3
"""
🔍 Model & PKL File Viewer
View contents and properties of pickle files easily
"""

import sys
import joblib
from pathlib import Path
import json

def view_pkl_contents(filepath):
    """Display pickle file contents"""
    try:
        data = joblib.load(filepath)
        
        print(f"\n{'='*70}")
        print(f"📦 FILE: {Path(filepath).name}")
        print(f"{'='*70}")
        print(f"Type: {type(data).__name__}")
        print(f"Path: {filepath}")
        
        file_size = Path(filepath).stat().st_size
        print(f"Size: {file_size:,} bytes ({file_size/1024:.2f} KB)")
        
        # Detailed analysis based on type
        if hasattr(data, '__class__'):
            print(f"Class: {data.__class__.__module__}.{data.__class__.__name__}")
        
        print(f"\n{'─'*70}")
        print("DETAILED PROPERTIES:")
        print(f"{'─'*70}")
        
        # For sklearn models
        if hasattr(data, 'get_params'):
            params = data.get_params()
            print(f"\n🔧 Model Parameters ({len(params)} total):")
            for key, val in list(params.items())[:10]:
                print(f"   • {key}: {val}")
            if len(params) > 10:
                print(f"   ... and {len(params) - 10} more")
        
        # For tree-based models
        if hasattr(data, 'n_estimators_'):
            print(f"\n🌳 Estimators: {data.n_estimators_}")
        
        if hasattr(data, 'n_features_in_'):
            print(f"📊 Input Features: {data.n_features_in_}")
            
        if hasattr(data, 'feature_importances_'):
            importances = data.feature_importances_
            print(f"\n⭐ Feature Importances ({len(importances)} features):")
            top_features = sorted(enumerate(importances), key=lambda x: x[1], reverse=True)[:5]
            for idx, (feature_idx, importance) in enumerate(top_features, 1):
                print(f"   {idx}. Feature {feature_idx}: {importance:.6f}")
        
        # For scalers
        if hasattr(data, 'scale_'):
            print(f"\n📈 Scaler Information:")
            print(f"   • Scale: {data.scale_}")
            print(f"   • Mean: {data.mean_}")
        
        if hasattr(data, 'feature_range'):
            print(f"   • Feature Range: {data.feature_range}")
            print(f"   • Min: {data.data_min_}")
            print(f"   • Max: {data.data_max_}")
        
        # Dictionary contents
        if isinstance(data, dict):
            print(f"\n📋 Dictionary Contents ({len(data)} keys):")
            for key in list(data.keys())[:10]:
                val = data[key]
                print(f"   • {key}: {type(val).__name__}")
            if len(data) > 10:
                print(f"   ... and {len(data) - 10} more keys")
        
        # String representation
        print(f"\n📄 Object String Representation:")
        obj_str = str(data)
        lines = obj_str.split('\n')
        for line in lines[:15]:
            print(f"   {line}")
        if len(lines) > 15:
            print(f"   ... ({len(lines) - 15} more lines)")
        
        print(f"\n{'='*70}\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Error loading {filepath}:")
        print(f"   {type(e).__name__}: {e}\n")
        return False

def list_all_models(models_dir="backend/models"):
    """List all pickle files in models directory"""
    models_path = Path(models_dir)
    
    if not models_path.exists():
        print(f"❌ Directory not found: {models_dir}")
        return
    
    pkl_files = list(models_path.glob("*.pkl"))
    
    if not pkl_files:
        print(f"⚠️  No .pkl files found in {models_dir}")
        return
    
    print(f"\n{'='*70}")
    print(f"📦 AVAILABLE MODELS IN: {models_dir}")
    print(f"{'='*70}")
    
    for pkl_file in pkl_files:
        size = pkl_file.stat().st_size
        try:
            data = joblib.load(pkl_file)
            data_type = type(data).__name__
            status = "✅"
        except Exception as e:
            data_type = "ERROR"
            status = "❌"
        
        print(f"{status} {pkl_file.name:<40} ({size:>10,} bytes) - {data_type}")
    
    print(f"{'='*70}\n")

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("\n🔍 PKL File Viewer")
        print("="*70)
        print("Usage:")
        print("  python view_pkl.py list              - List all models")
        print("  python view_pkl.py <filename>        - View specific model")
        print("  python view_pkl.py all               - View all models")
        print("\nExamples:")
        print("  python view_pkl.py banking_anomaly_model.pkl")
        print("  python view_pkl.py banking_scaler.pkl")
        print("="*70 + "\n")
        
        # Show available models by default
        list_all_models()
        return
    
    command = sys.argv[1]
    
    if command == "list":
        list_all_models()
    elif command == "all":
        models_dir = Path("backend/models")
        for pkl_file in models_dir.glob("*.pkl"):
            view_pkl_contents(pkl_file)
    else:
        # Try as filename directly
        filepath = Path(command)
        if not filepath.exists():
            # Try in models directory
            filepath = Path("backend/models") / command
        
        if filepath.exists():
            view_pkl_contents(filepath)
        else:
            print(f"❌ File not found: {command}")

if __name__ == "__main__":
    main()
