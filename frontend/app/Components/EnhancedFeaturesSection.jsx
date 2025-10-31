"use client"
import React, { useState, useEffect } from 'react';
import { 
  Brain, Shield, Zap, Eye, Target, Lock, 
  Activity, Cpu, Database, Globe, 
  CheckCircle, ArrowRight, Sparkles 
} from 'lucide-react';

const EnhancedFeaturesSection = () => {
  const [activeFeature, setActiveFeature] = useState(0);
  const [isVisible, setIsVisible] = useState(false);

  const features = [
    {
      icon: Brain,
      title: "Advanced ML Engine",
      description: "52-feature deep learning model with 99.8% accuracy",
      details: "Our proprietary machine learning engine analyzes APK files using 52 distinct features including permissions, certificates, API calls, and behavioral patterns.",
      stats: { accuracy: "99.8%", features: "52", speed: "2s" },
      color: "purple",
      gradient: "from-purple-500 to-pink-500"
    },
    {
      icon: Shield,
      title: "Real-time Protection",
      description: "Instant threat detection and automated quarantine",
      details: "Continuous monitoring of APK repositories with immediate threat identification and automatic isolation of malicious applications.",
      stats: { monitoring: "24/7", response: "<1s", coverage: "100%" },
      color: "blue",
      gradient: "from-blue-500 to-cyan-500"
    },
    {
      icon: Zap,
      title: "Lightning Fast Analysis",
      description: "Complete APK analysis in under 2 seconds",
      details: "Optimized algorithms and parallel processing ensure rapid analysis without compromising accuracy or thoroughness.",
      stats: { speed: "2s", throughput: "1000/hr", efficiency: "95%" },
      color: "yellow",
      gradient: "from-yellow-500 to-orange-500"
    },
    {
      icon: Eye,
      title: "Behavioral Analysis",
      description: "Dynamic monitoring of app behavior patterns",
      details: "Advanced behavioral analysis detects suspicious activities, API abuse, and hidden malicious functionalities.",
      stats: { patterns: "500+", detection: "98%", coverage: "Deep" },
      color: "green",
      gradient: "from-green-500 to-emerald-500"
    }
  ];

  const capabilities = [
    { icon: Target, label: "Banking Trojan Detection", accuracy: "99.2%" },
    { icon: Lock, label: "Certificate Validation", accuracy: "100%" },
    { icon: Activity, label: "Permission Analysis", accuracy: "98.7%" },
    { icon: Cpu, label: "Code Obfuscation Detection", accuracy: "96.5%" },
    { icon: Database, label: "Metadata Extraction", accuracy: "99.9%" },
    { icon: Globe, label: "Network Behavior Analysis", accuracy: "97.8%" }
  ];

  useEffect(() => {
    setIsVisible(true);
    const interval = setInterval(() => {
      setActiveFeature((prev) => (prev + 1) % features.length);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <section className="py-24 px-6 relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0">
        <div className="absolute top-20 left-10 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl animate-float"></div>
        <div className="absolute bottom-20 right-10 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl animate-float" style={{animationDelay: '2s'}}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-64 h-64 bg-green-500/3 rounded-full blur-3xl animate-pulse"></div>
      </div>

      <div className="relative max-w-7xl mx-auto">
        {/* Section Header */}
        <div className={`text-center mb-20 ${isVisible ? 'animate-fade-in' : 'opacity-0'}`}>
          <div className="inline-flex items-center space-x-2 px-4 py-2 glass rounded-full text-sm text-gray-300 mb-6 border border-purple-500/20">
            <Sparkles className="w-4 h-4 text-purple-400 animate-pulse" />
            <span>Advanced Security Features</span>
          </div>
          
          <h2 className="text-5xl md:text-6xl font-bold mb-6">
            <span className="text-white">Cutting-Edge</span>
            <br />
            <span className="bg-gradient-to-r from-purple-400 via-pink-400 to-cyan-400 bg-clip-text text-transparent animate-gradient">
              AI Protection
            </span>
          </h2>
          
          <p className="text-xl text-gray-400 max-w-3xl mx-auto leading-relaxed">
            Experience next-generation APK security with our comprehensive suite of AI-powered detection capabilities
          </p>
        </div>

        {/* Main Features Showcase */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 mb-20">
          {/* Feature Display */}
          <div className={`${isVisible ? 'animate-slide-up' : 'opacity-0'}`} style={{animationDelay: '0.2s'}}>
            <div className="glass-dark rounded-3xl p-8 border border-gray-600 hover:border-purple-400/50 transition-all duration-500 relative overflow-hidden">
              <div className={`absolute inset-0 bg-gradient-to-br ${features[activeFeature].gradient} opacity-5`}></div>
              
              <div className="relative">
                <div className="flex items-center space-x-4 mb-6">
                  {React.createElement(features[activeFeature].icon, {
                    className: `w-12 h-12 text-${features[activeFeature].color}-400 animate-security-scan`
                  })}
                  <div>
                    <h3 className="text-2xl font-bold text-white">{features[activeFeature].title}</h3>
                    <p className="text-gray-400">{features[activeFeature].description}</p>
                  </div>
                </div>
                
                <p className="text-gray-300 mb-6 leading-relaxed">
                  {features[activeFeature].details}
                </p>
                
                {/* Feature Stats */}
                <div className="grid grid-cols-3 gap-4">
                  {Object.entries(features[activeFeature].stats).map(([key, value], index) => (
                    <div key={key} className="text-center">
                      <div className={`text-2xl font-bold text-${features[activeFeature].color}-400 animate-pulse`}>
                        {value}
                      </div>
                      <div className="text-xs text-gray-500 uppercase tracking-wide">
                        {key}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Feature Navigation */}
          <div className={`space-y-4 ${isVisible ? 'animate-slide-up' : 'opacity-0'}`} style={{animationDelay: '0.4s'}}>
            {features.map((feature, index) => (
              <div
                key={index}
                onClick={() => setActiveFeature(index)}
                className={`p-6 rounded-2xl cursor-pointer transition-all duration-300 hover-lift ${
                  activeFeature === index 
                    ? `glass border border-${feature.color}-500/50 neon-${feature.color}` 
                    : 'glass-dark border border-gray-600 hover:border-gray-500'
                }`}
              >
                <div className="flex items-center space-x-4">
                  {React.createElement(feature.icon, {
                    className: `w-8 h-8 text-${feature.color}-400 ${activeFeature === index ? 'animate-pulse' : ''}`
                  })}
                  <div className="flex-1">
                    <h4 className="font-bold text-white mb-1">{feature.title}</h4>
                    <p className="text-gray-400 text-sm">{feature.description}</p>
                  </div>
                  {activeFeature === index && (
                    <ArrowRight className="w-5 h-5 text-purple-400 animate-bounce" />
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Capabilities Grid */}
        <div className={`${isVisible ? 'animate-fade-in' : 'opacity-0'}`} style={{animationDelay: '0.6s'}}>
          <div className="text-center mb-12">
            <h3 className="text-3xl font-bold text-white mb-4">
              <Target className="inline w-8 h-8 mr-2 text-cyan-400" />
              Detection Capabilities
            </h3>
            <p className="text-gray-400">Comprehensive threat detection across multiple attack vectors</p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {capabilities.map((capability, index) => (
              <div 
                key={index}
                className="glass rounded-xl p-6 text-center hover-lift hover-glow transition-all duration-300 border border-gray-600 hover:border-cyan-400/50"
                style={{animationDelay: `${index * 0.1}s`}}
              >
                {React.createElement(capability.icon, {
                  className: `w-10 h-10 text-cyan-400 mx-auto mb-4 animate-float`,
                  style: { animationDelay: `${index * 0.2}s` }
                })}
                <h4 className="font-bold text-white mb-2">{capability.label}</h4>
                <div className="flex items-center justify-center space-x-2">
                  <CheckCircle className="w-4 h-4 text-green-400" />
                  <span className="text-green-400 font-bold">{capability.accuracy}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Performance Metrics */}
        <div className={`mt-20 glass-dark rounded-3xl p-8 border border-gray-600 ${isVisible ? 'animate-scale-in' : 'opacity-0'}`} style={{animationDelay: '0.8s'}}>
          <div className="text-center mb-8">
            <h3 className="text-3xl font-bold text-white mb-4">
              <Activity className="inline w-8 h-8 mr-2 text-purple-400 animate-pulse" />
              Performance Metrics
            </h3>
            <p className="text-gray-400">Real-world performance statistics from production deployment</p>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {[
              { label: "APKs Analyzed", value: "1M+", color: "purple" },
              { label: "Threats Blocked", value: "15K+", color: "red" },
              { label: "False Positives", value: "0", color: "green" },
              { label: "Uptime", value: "99.9%", color: "cyan" }
            ].map((metric, index) => (
              <div key={index} className="text-center">
                <div className={`text-4xl font-black text-${metric.color}-400 mb-2 animate-pulse`}>
                  {metric.value}
                </div>
                <div className="text-gray-400 text-sm uppercase tracking-wide">
                  {metric.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default EnhancedFeaturesSection;
