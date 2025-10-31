"use client"
import React, { useState, useEffect } from 'react';
import { ArrowRight, Play, Shield, Zap, Brain, Lock, Cpu, Eye, Target, Sparkles } from 'lucide-react';

const EnhancedHeroSection = () => {
  const [isVisible, setIsVisible] = useState(false);
  const [currentStat, setCurrentStat] = useState(0);
  const [scanAnimation, setScanAnimation] = useState(false);
  
  const stats = [
    { icon: Shield, label: "99.8% Detection Rate", value: "99.8%", desc: "Accuracy", color: "text-green-400" },
    { icon: Zap, label: "2s Analysis Time", value: "2s", desc: "Speed", color: "text-yellow-400" },
    { icon: Brain, label: "AI-Powered Engine", value: "52", desc: "Features", color: "text-purple-400" },
    { icon: Lock, label: "Zero False Positives", value: "0", desc: "False+", color: "text-cyan-400" }
  ];

  const threatTypes = [
    "Banking Trojans", "SMS Interceptors", "Credential Stealers", "Phishing Apps", 
    "Fake Certificates", "Malicious Permissions", "Code Obfuscation", "Data Exfiltration"
  ];

  useEffect(() => {
    setIsVisible(true);
    const statInterval = setInterval(() => {
      setCurrentStat((prev) => (prev + 1) % stats.length);
    }, 3000);
    
    const scanInterval = setInterval(() => {
      setScanAnimation(true);
      setTimeout(() => setScanAnimation(false), 2000);
    }, 5000);
    
    return () => {
      clearInterval(statInterval);
      clearInterval(scanInterval);
    };
  }, []);

  return (
    <section className="relative text-center py-24 px-6 overflow-hidden min-h-screen flex items-center">
      {/* Dynamic Background Effects */}
      <div className="absolute inset-0 overflow-hidden">
        {/* Floating Orbs */}
        <div className="absolute top-20 left-10 w-72 h-72 bg-purple-500/10 rounded-full blur-3xl animate-float"></div>
        <div className="absolute bottom-20 right-10 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-float" style={{animationDelay: '2s'}}></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-64 h-64 bg-green-500/5 rounded-full blur-3xl animate-pulse"></div>
        
        {/* Grid Pattern */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(139,92,246,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(139,92,246,0.03)_1px,transparent_1px)] bg-[size:50px_50px]"></div>
        
        {/* Scanning Lines */}
        <div className={`absolute inset-0 ${scanAnimation ? 'opacity-100' : 'opacity-0'} transition-opacity duration-500`}>
          <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-scan"></div>
          <div className="absolute bottom-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-purple-400 to-transparent animate-scan" style={{animationDelay: '0.5s'}}></div>
        </div>
      </div>

      {/* Matrix Rain Effect */}
      <div className="absolute inset-0 pointer-events-none">
        {[...Array(30)].map((_, i) => (
          <div
            key={i}
            className="absolute w-px h-20 bg-gradient-to-b from-transparent via-green-400/20 to-transparent animate-matrix"
            style={{
              left: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 3}s`,
              animationDuration: `${3 + Math.random() * 2}s`
            }}
          />
        ))}
      </div>

      <div className="relative max-w-7xl mx-auto">
        {/* AI Status Badge */}
        <div className={`inline-flex items-center space-x-3 px-6 py-3 glass rounded-full text-sm text-gray-300 mb-8 border border-purple-500/30 animate-pulse-glow ${isVisible ? 'animate-slide-up' : 'opacity-0'}`}>
          <div className="relative">
            <Cpu className="w-4 h-4 text-purple-400 animate-spin" />
          </div>
          <span className="font-medium">🧠 Advanced ML Threat Detection System</span>
          <div className="flex items-center space-x-2">
            <div className="w-2 h-2 bg-green-400 rounded-full animate-ping"></div>
            <span className="px-2 py-1 bg-green-500/20 rounded-full text-xs text-green-400 font-bold">ACTIVE</span>
          </div>
        </div>
        
        {/* Main Heading with Typewriter Effect */}
        <div className={`${isVisible ? 'animate-scale-in' : 'opacity-0'}`} style={{animationDelay: '0.2s'}}>
          <h1 className="text-6xl md:text-8xl font-black mb-8 leading-tight">
            <div className="relative">
              <span className="text-white block mb-4">Detect Fake Banking Apps</span>
              <div className="absolute -inset-2 bg-gradient-to-r from-purple-600/20 to-cyan-600/20 blur-2xl rounded-lg"></div>
            </div>
            <span className="bg-gradient-to-r from-purple-400 via-pink-400 to-cyan-400 bg-clip-text text-transparent animate-gradient block mb-4">
              Before They Strike
            </span>
            <div className="relative inline-block">
              <span className="bg-gradient-to-r from-cyan-400 via-green-400 to-emerald-400 bg-clip-text text-transparent">
                Your AI Guardian
              </span>
              <Sparkles className="absolute -top-2 -right-8 w-8 h-8 text-yellow-400 animate-pulse" />
            </div>
          </h1>
        </div>
        
        {/* Enhanced Subtitle */}
        <div className={`${isVisible ? 'animate-fade-in' : 'opacity-0'}`} style={{animationDelay: '0.4s'}}>
          <p className="text-2xl md:text-3xl text-gray-300 mb-16 max-w-5xl mx-auto leading-relaxed">
            <span className="text-white font-bold bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
              AI-powered real-time protection
            </span> against sophisticated malicious APKs disguised as legitimate banking applications.
            <br />
            <span className="text-purple-300 text-xl">
              Safeguard millions from financial fraud with cutting-edge machine learning detection.
            </span>
          </p>
        </div>

        {/* Dynamic Stats Dashboard */}
        <div className={`mb-16 ${isVisible ? 'animate-slide-up' : 'opacity-0'}`} style={{animationDelay: '0.6s'}}>
          <div className="glass-dark rounded-3xl p-8 max-w-2xl mx-auto border border-purple-500/20 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-r from-purple-500/5 via-transparent to-cyan-500/5"></div>
            <div className="relative flex items-center justify-center space-x-8">
              <div className="text-center">
                {React.createElement(stats[currentStat].icon, {
                  className: `w-12 h-12 ${stats[currentStat].color} animate-security-scan mx-auto mb-2`
                })}
                <div className={`text-4xl font-black ${stats[currentStat].color} animate-pulse mb-1`}>
                  {stats[currentStat].value}
                </div>
                <div className="text-gray-300 text-sm font-medium">
                  {stats[currentStat].desc}
                </div>
              </div>
              <div className="h-16 w-px bg-gradient-to-b from-transparent via-purple-400 to-transparent"></div>
              <div className="text-left">
                <div className="text-white font-bold text-lg mb-2">
                  {stats[currentStat].label.split(' ').slice(1).join(' ')}
                </div>
                <div className="text-gray-400 text-sm">
                  Real-time ML Analysis
                </div>
              </div>
            </div>
          </div>
        </div>
        
        {/* Action Buttons with Enhanced Effects */}
        <div className={`flex flex-col sm:flex-row items-center justify-center space-y-6 sm:space-y-0 sm:space-x-8 mb-16 ${isVisible ? 'animate-scale-in' : 'opacity-0'}`} style={{animationDelay: '0.8s'}}>
          <button 
            className="group relative flex items-center space-x-4 px-12 py-5 bg-gradient-to-r from-purple-500 via-pink-500 to-cyan-500 text-white rounded-2xl font-black text-xl hover:from-purple-600 hover:via-pink-600 hover:to-cyan-600 transition-all duration-300 shadow-2xl hover:shadow-purple-500/50 hover-lift neon-purple animate-gradient overflow-hidden"
            onClick={() => {
              document.getElementById('scan-section')?.scrollIntoView({ 
                behavior: 'smooth' 
              });
            }}
          >
            <div className="absolute inset-0 bg-gradient-to-r from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 animate-scan"></div>
            <Shield className="w-8 h-8 animate-security-scan" />
            <span>Start AI Scan</span>
            <ArrowRight className="w-6 h-6 group-hover:translate-x-2 transition-transform duration-300" />
          </button>
          
          <button className="group flex items-center space-x-4 px-12 py-5 glass-dark text-white rounded-2xl font-bold text-xl hover:bg-white/10 transition-all duration-300 border border-gray-600 hover:border-purple-400 hover-lift">
            <Play className="w-6 h-6 group-hover:scale-125 transition-transform duration-300" />
            <span>Watch Demo</span>
          </button>
        </div>

        {/* Threat Detection Showcase */}
        <div className={`mb-16 ${isVisible ? 'animate-fade-in' : 'opacity-0'}`} style={{animationDelay: '1s'}}>
          <div className="text-center mb-8">
            <h3 className="text-2xl font-bold text-white mb-4">
              <Eye className="inline w-8 h-8 mr-2 text-cyan-400" />
              Detects Advanced Threats
            </h3>
          </div>
          <div className="flex flex-wrap justify-center gap-3 max-w-4xl mx-auto">
            {threatTypes.map((threat, index) => (
              <div 
                key={index} 
                className="px-4 py-2 glass rounded-full text-sm text-gray-300 border border-red-500/20 hover:border-red-400/40 transition-all duration-300 hover-lift"
                style={{animationDelay: `${index * 0.1}s`}}
              >
                <Target className="inline w-4 h-4 mr-2 text-red-400" />
                {threat}
              </div>
            ))}
          </div>
        </div>

        {/* Enhanced Security Features Grid */}
        <div className={`grid grid-cols-2 md:grid-cols-4 gap-6 ${isVisible ? 'animate-fade-in' : 'opacity-0'}`} style={{animationDelay: '1.2s'}}>
          {[
            { icon: Brain, label: "ML Engine", desc: "52 Feature Analysis", color: "purple", metric: "52+" },
            { icon: Zap, label: "Real-time", desc: "2s Detection", color: "yellow", metric: "2s" },
            { icon: Shield, label: "99.8% Accurate", desc: "Proven Results", color: "green", metric: "99.8%" },
            { icon: Lock, label: "Zero False+", desc: "Reliable Protection", color: "cyan", metric: "0%" }
          ].map((feature, index) => (
            <div key={index} className={`glass rounded-2xl p-6 text-center hover-lift hover-glow transition-all duration-300 border border-${feature.color}-500/20 relative overflow-hidden group`}>
              <div className={`absolute inset-0 bg-gradient-to-br from-${feature.color}-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300`}></div>
              <div className="relative">
                {React.createElement(feature.icon, {
                  className: `w-10 h-10 text-${feature.color}-400 mx-auto mb-3 animate-float`,
                  style: { animationDelay: `${index * 0.5}s` }
                })}
                <div className={`text-3xl font-black text-${feature.color}-400 mb-2`}>{feature.metric}</div>
                <div className={`text-${feature.color}-400 font-bold text-lg mb-1`}>{feature.label}</div>
                <div className="text-gray-400 text-sm">{feature.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default EnhancedHeroSection;
