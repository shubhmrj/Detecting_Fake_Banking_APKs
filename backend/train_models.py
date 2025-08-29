"""
Model Training Script
Run this to train ML models for APK classification
"""

from ml_integration import ml_analyzer

def main():
    print("Starting ML Model Training for APK Classification")
    print("=" * 50)
    
    # Check current model status
    status = ml_analyzer.get_model_status()
    print(f"Current status: {status}")
    
    # Train models with synthetic data
    print("\nTraining models with 2000 synthetic samples...")
    result = ml_analyzer.train_models(num_samples=2000)
    
    print("\nTraining Results:")
    print(f"Status: {result['status']}")
    print(f"Models trained: {result['models_trained']}")
    print(f"Training samples: {result['training_samples']}")
    
    print("\nModel Performance:")
    for model_name, metrics in result['model_metrics'].items():
        print(f"\n{model_name.upper()}:")
        print(f"  Accuracy: {metrics['accuracy']:.4f}")
        print(f"  AUC Score: {metrics['auc_score']:.4f}")
    
    # Test model status after training
    final_status = ml_analyzer.get_model_status()
    print(f"\nFinal model status: {final_status}")
    
    print("\n" + "=" * 50)
    print("Model training completed successfully!")
    print("Models are now ready for APK analysis.")

if __name__ == '__main__':
    main()
