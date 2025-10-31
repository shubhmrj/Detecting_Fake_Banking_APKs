"use client"
import React, { useState, useEffect } from 'react';
import { Shield, Menu, X, Brain, Zap, Target, Github, ExternalLink } from 'lucide-react';

const EnhancedHeader = () => {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
    
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navItems = [
    { label: 'Scan APK', href: '#scan-section', icon: Target },
    { label: 'Features', href: '#features', icon: Brain },
    { label: 'Demo', href: '#demo', icon: Zap },
    { label: 'API', href: '#api', icon: ExternalLink }
  ];

  return (
    <header className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
      isScrolled 
        ? 'glass-dark backdrop-blur-xl border-b border-purple-500/20' 
        : 'bg-transparent'
    }`}>
      <div className="max-w-7xl mx-auto px-6">
        <div className="flex items-center justify-between h-20">
          {/* Logo */}
          <div className={`flex items-center space-x-3 ${isVisible ? 'animate-slide-up' : 'opacity-0'}`}>
            <div className="relative">
              <div className="w-12 h-12 bg-gradient-to-r from-purple-500 to-cyan-500 rounded-xl flex items-center justify-center animate-pulse-glow">
                <Shield className="w-7 h-7 text-white animate-security-scan" />
              </div>
              <div className="absolute -inset-1 bg-gradient-to-r from-purple-600/20 to-cyan-600/20 blur-lg rounded-xl animate-pulse"></div>
            </div>
            <div>
              <h1 className="text-2xl font-black text-white">
                APK<span className="bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">Guard</span>
              </h1>
              <p className="text-xs text-gray-400 font-medium">AI Security Platform</p>
            </div>
          </div>

          {/* Desktop Navigation */}
          <nav className={`hidden md:flex items-center space-x-8 ${isVisible ? 'animate-fade-in' : 'opacity-0'}`} style={{animationDelay: '0.2s'}}>
            {navItems.map((item, index) => (
              <a
                key={item.label}
                href={item.href}
                className="group flex items-center space-x-2 px-4 py-2 rounded-lg text-gray-300 hover:text-white transition-all duration-300 hover:bg-white/5"
                onClick={(e) => {
                  e.preventDefault();
                  document.querySelector(item.href)?.scrollIntoView({ behavior: 'smooth' });
                }}
              >
                {React.createElement(item.icon, {
                  className: 'w-4 h-4 group-hover:text-purple-400 transition-colors duration-300'
                })}
                <span className="font-medium">{item.label}</span>
              </a>
            ))}
          </nav>

          {/* Action Buttons */}
          <div className={`hidden md:flex items-center space-x-4 ${isVisible ? 'animate-slide-up' : 'opacity-0'}`} style={{animationDelay: '0.4s'}}>
            <button className="flex items-center space-x-2 px-6 py-3 glass rounded-lg text-white hover:bg-white/10 transition-all duration-300 border border-gray-600 hover:border-purple-400">
              <Github className="w-4 h-4" />
              <span>GitHub</span>
            </button>
            <button 
              className="flex items-center space-x-2 px-6 py-3 bg-gradient-to-r from-purple-500 to-cyan-500 text-white rounded-lg font-bold hover:from-purple-600 hover:to-cyan-600 transition-all duration-300 shadow-lg hover:shadow-purple-500/25 hover-lift"
              onClick={() => {
                document.getElementById('scan-section')?.scrollIntoView({ behavior: 'smooth' });
              }}
            >
              <Shield className="w-4 h-4" />
              <span>Start Scan</span>
            </button>
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="md:hidden p-2 rounded-lg text-gray-300 hover:text-white hover:bg-white/10 transition-all duration-300"
          >
            {isMobileMenuOpen ? (
              <X className="w-6 h-6" />
            ) : (
              <Menu className="w-6 h-6" />
            )}
          </button>
        </div>

        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="md:hidden absolute top-full left-0 right-0 glass-dark backdrop-blur-xl border-b border-purple-500/20 animate-slide-up">
            <div className="px-6 py-6 space-y-4">
              {navItems.map((item) => (
                <a
                  key={item.label}
                  href={item.href}
                  className="flex items-center space-x-3 px-4 py-3 rounded-lg text-gray-300 hover:text-white hover:bg-white/10 transition-all duration-300"
                  onClick={(e) => {
                    e.preventDefault();
                    document.querySelector(item.href)?.scrollIntoView({ behavior: 'smooth' });
                    setIsMobileMenuOpen(false);
                  }}
                >
                  {React.createElement(item.icon, {
                    className: 'w-5 h-5 text-purple-400'
                  })}
                  <span className="font-medium">{item.label}</span>
                </a>
              ))}
              <div className="pt-4 border-t border-gray-700 space-y-3">
                <button className="w-full flex items-center justify-center space-x-2 px-4 py-3 glass rounded-lg text-white hover:bg-white/10 transition-all duration-300">
                  <Github className="w-4 h-4" />
                  <span>GitHub</span>
                </button>
                <button 
                  className="w-full flex items-center justify-center space-x-2 px-4 py-3 bg-gradient-to-r from-purple-500 to-cyan-500 text-white rounded-lg font-bold hover:from-purple-600 hover:to-cyan-600 transition-all duration-300"
                  onClick={() => {
                    document.getElementById('scan-section')?.scrollIntoView({ behavior: 'smooth' });
                    setIsMobileMenuOpen(false);
                  }}
                >
                  <Shield className="w-4 h-4" />
                  <span>Start Scan</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </header>
  );
};

export default EnhancedHeader;
