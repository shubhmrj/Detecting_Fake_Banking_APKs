import React from 'react';
import EnhancedHeader from './Components/EnhancedHeader';
import EnhancedHeroSection from './Components/EnhancedHeroSection';
import EnhancedScanSection from './Components/EnhancedScanSection';
import EnhancedFeaturesSection from './Components/EnhancedFeaturesSection';
import Footer from './Components/Footer';

const EnhancedHomePage = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-indigo-900 to-purple-800 relative overflow-hidden">
      {/* Dynamic Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        {/* Floating Orbs */}
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-float"></div>
        <div className="absolute top-1/3 right-1/4 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl animate-float" style={{animationDelay: '2s'}}></div>
        <div className="absolute bottom-1/4 left-1/3 w-72 h-72 bg-pink-500/10 rounded-full blur-3xl animate-float" style={{animationDelay: '4s'}}></div>
        <div className="absolute top-2/3 right-1/3 w-64 h-64 bg-green-500/8 rounded-full blur-3xl animate-pulse"></div>
        
        {/* Animated Grid Pattern */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(139,92,246,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(139,92,246,0.02)_1px,transparent_1px)] bg-[size:60px_60px] animate-pulse"></div>
        
        {/* Scanning Lines */}
        <div className="absolute top-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-purple-400/30 to-transparent animate-scan"></div>
        <div className="absolute bottom-0 left-0 w-full h-px bg-gradient-to-r from-transparent via-cyan-400/30 to-transparent animate-scan" style={{animationDelay: '1s'}}></div>
        <div className="absolute top-1/2 left-0 w-full h-px bg-gradient-to-r from-transparent via-green-400/20 to-transparent animate-scan" style={{animationDelay: '2s'}}></div>
        
        {/* Matrix Rain Effect */}
        {[...Array(50)].map((_, i) => (
          <div
            key={i}
            className="absolute w-px h-16 bg-gradient-to-b from-transparent via-green-400/10 to-transparent animate-matrix"
            style={{
              left: `${Math.random() * 100}%`,
              animationDelay: `${Math.random() * 5}s`,
              animationDuration: `${4 + Math.random() * 3}s`
            }}
          />
        ))}
      </div>
      
      {/* Main Content */}
      <div className="relative z-10">
        <EnhancedHeader />
        <main>
          <EnhancedHeroSection />
          <div id="scan-section">
            <EnhancedScanSection />
          </div>
          <div id="features">
            <EnhancedFeaturesSection />
          </div>
        </main>
        <Footer />
      </div>
      
      {/* Floating Action Button */}
      <button 
        className="fixed bottom-8 right-8 w-16 h-16 bg-gradient-to-r from-purple-500 to-cyan-500 rounded-full flex items-center justify-center text-white shadow-2xl hover:shadow-purple-500/50 transition-all duration-300 hover:scale-110 neon-purple z-50"
        onClick={() => {
          document.getElementById('scan-section')?.scrollIntoView({ behavior: 'smooth' });
        }}
        title="Quick Scan"
      >
        <svg className="w-8 h-8 animate-pulse" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      </button>
    </div>
  );
};

export default EnhancedHomePage;
