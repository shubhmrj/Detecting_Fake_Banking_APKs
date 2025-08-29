"""
ML Integration Module for Enhanced APK Analysis
Integrates trained ML models with the APK analyzer
"""

import os
import json
from ml_trainer import APKMLTrainer
from apk_analyzer import EnhancedAPKAnalyzer

class MLEnhancedAPKAnalyzer:
    """APK Analyzer with ML model integration"""
    
    def __init__(self, model_dir='models'):
        self.base_analyzer = EnhancedAPKAnalyzer()
        self.ml_trainer = APKMLTrainer()
        self.model_dir = model_dir
        self.models_loaded = False
        
        # Try to load existing models
        self._load_models_if_available()
    
    def _load_models_if_available(self):
        """Load ML models if they exist"""
        try:
            if os.path.exists(self.model_dir) and os.path.exists(os.path.join(self.model_dir, 'model_metadata.json')):
                self.ml_trainer.load_models(self.model_dir)
                self.models_loaded = True
                print("ML models loaded successfully")
            else:
                print("No trained models found. Use train_models() to create them.")
        except Exception as e:
            print(f"Error loading models: {e}")
            self.models_loaded = False
    
    def train_models(self, num_samples=2000):
        """Train ML models with synthetic data"""
        print("Starting ML model training...")
        
        # Generate training data
        training_data = self.ml_trainer.generate_synthetic_training_data(num_samples)
        
        # Train models
        models = self.ml_trainer.train_models(training_data)
        
        # Save models
        self.ml_trainer.save_models(self.model_dir)
        
        self.models_loaded = True
        print("ML model training completed and saved!")
        
        return {
            'status': 'success',
            'models_trained': list(models.keys()),
            'training_samples': num_samples,
            'model_metrics': self.ml_trainer.model_metrics
        }
    
    def analyze_apk_with_ml(self, apk_path, use_ml=True):
        """Analyze APK with both static analysis and ML prediction"""
        # Perform base static analysis
        base_analysis = self.base_analyzer.analyze_apk(apk_path)
        
        if 'error' in base_analysis:
            return base_analysis
        
        # Add ML prediction if models are available
        ml_results = {}
        if use_ml and self.models_loaded:
            try:
                # Extract ML features
                ml_features = self.ml_trainer.extract_ml_features(base_analysis)
                
                # Get predictions from all models
                ml_predictions = {}
                for model_name in self.ml_trainer.models.keys():
                    prediction = self.ml_trainer.predict(ml_features, model_name)
                    ml_predictions[model_name] = prediction
                
                # Ensemble prediction (majority vote with confidence weighting)
                ensemble_prediction = self._ensemble_predict(ml_predictions)
                
                # Get feature importance
                feature_importance = self.ml_trainer.get_feature_importance('random_forest')
                
                ml_results = {
                    'ml_enabled': True,
                    'individual_predictions': ml_predictions,
                    'ensemble_prediction': ensemble_prediction,
                    'ml_features': ml_features,
                    'feature_importance': dict(list(feature_importance.items())[:10]),  # Top 10 features
                    'model_metrics': self.ml_trainer.model_metrics
                }
                
                # Update risk assessment with ML insights
                self._update_risk_with_ml(base_analysis, ensemble_prediction)
                
            except Exception as e:
                ml_results = {
                    'ml_enabled': False,
                    'ml_error': str(e)
                }
        else:
            ml_results = {
                'ml_enabled': False,
                'reason': 'Models not loaded' if not self.models_loaded else 'ML disabled'
            }
        
        # Combine results
        enhanced_analysis = base_analysis.copy()
        enhanced_analysis['ml_analysis'] = ml_results
        
        return enhanced_analysis
    
    def _ensemble_predict(self, ml_predictions):
        """Create ensemble prediction from multiple models"""
        predictions = []
        confidences = []
        malicious_probs = []
        
        for model_name, pred in ml_predictions.items():
            predictions.append(pred['prediction'])
            confidences.append(pred['confidence'])
            malicious_probs.append(pred['probability_malicious'])
        
        # Weighted average based on confidence
        total_confidence = sum(confidences)
        if total_confidence > 0:
            weighted_malicious_prob = sum(prob * conf for prob, conf in zip(malicious_probs, confidences)) / total_confidence
        else:
            weighted_malicious_prob = sum(malicious_probs) / len(malicious_probs)
        
        # Majority vote
        majority_prediction = 1 if sum(predictions) > len(predictions) / 2 else 0
        
        # Final prediction (combine majority vote with weighted probability)
        final_prediction = 1 if weighted_malicious_prob > 0.5 else 0
        
        return {
            'prediction': final_prediction,
            'probability_malicious': weighted_malicious_prob,
            'probability_legitimate': 1 - weighted_malicious_prob,
            'confidence': max(confidences),
            'majority_vote': majority_prediction,
            'model_agreement': len(set(predictions)) == 1,  # All models agree
            'ensemble_method': 'weighted_confidence'
        }
    
    def _update_risk_with_ml(self, base_analysis, ml_prediction):
        """Update risk assessment with ML insights"""
        security_analysis = base_analysis.get('security_analysis', {})
        
        # Adjust risk score based on ML prediction
        original_risk = security_analysis.get('risk_score', 0)
        ml_risk = ml_prediction['probability_malicious'] * 100
        
        # Weighted combination (70% static analysis, 30% ML)
        combined_risk = (original_risk * 0.7) + (ml_risk * 0.3)
        
        # Update security analysis
        security_analysis['risk_score'] = min(combined_risk, 100)
        security_analysis['ml_risk_score'] = ml_risk
        security_analysis['original_static_risk'] = original_risk
        
        # Update risk level
        if security_analysis['risk_score'] >= 80:
            security_analysis['risk_level'] = 'CRITICAL'
        elif security_analysis['risk_score'] >= 60:
            security_analysis['risk_level'] = 'HIGH'
        elif security_analysis['risk_score'] >= 40:
            security_analysis['risk_level'] = 'MEDIUM'
        elif security_analysis['risk_score'] >= 20:
            security_analysis['risk_level'] = 'LOW'
        else:
            security_analysis['risk_level'] = 'MINIMAL'
        
        security_analysis['is_suspicious'] = security_analysis['risk_score'] >= 60
        
        # Add ML-based risk factors
        if ml_prediction['prediction'] == 1:
            security_analysis['risk_factors'].append(f"ML models predict malicious (confidence: {ml_prediction['confidence']:.2f})")
        
        if not ml_prediction['model_agreement']:
            security_analysis['risk_factors'].append("ML models show disagreement in prediction")
        
        # Add ML explanation
        security_analysis['ml_explanation'] = {
            'prediction': 'Malicious' if ml_prediction['prediction'] == 1 else 'Legitimate',
            'confidence': ml_prediction['confidence'],
            'model_agreement': ml_prediction['model_agreement'],
            'risk_contribution': f"ML analysis contributed {abs(ml_risk - original_risk):.1f} points to risk score"
        }
    
    def get_model_status(self):
        """Get status of ML models"""
        status = {
            'models_loaded': self.models_loaded,
            'model_count': len(self.ml_trainer.models),
            'available_models': list(self.ml_trainer.models.keys()) if self.models_loaded else [],
            'model_dir': self.model_dir
        }
        
        if self.models_loaded:
            status['model_metrics'] = self.ml_trainer.model_metrics
            status['feature_count'] = len(self.ml_trainer.feature_columns)
        
        return status
    
    def retrain_with_real_data(self, analysis_results, labels):
        """Retrain models with real APK analysis data"""
        print("Retraining models with real data...")
        
        # Extract features from real analysis results
        training_data = []
        for analysis, label in zip(analysis_results, labels):
            features = self.ml_trainer.extract_ml_features(analysis)
            features['label'] = label
            training_data.append(features)
        
        # Convert to DataFrame
        import pandas as pd
        df = pd.DataFrame(training_data)
        
        # Retrain models
        models = self.ml_trainer.train_models(df)
        
        # Save updated models
        self.ml_trainer.save_models(self.model_dir)
        
        print("Model retraining completed!")
        return {
            'status': 'success',
            'training_samples': len(training_data),
            'model_metrics': self.ml_trainer.model_metrics
        }

# Global instance for use in Flask app
ml_analyzer = MLEnhancedAPKAnalyzer()
