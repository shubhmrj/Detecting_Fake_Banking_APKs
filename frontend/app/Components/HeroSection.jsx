"use client"
import React from 'react';
import { ArrowRight, Play } from 'lucide-react';

const HeroSection = () => {
  return (
    <section className="text-center py-20 px-6">
      <div className="max-w-4xl mx-auto">
        <div className="inline-flex items-center space-x-2 px-4 py-2 bg-black/20 rounded-full text-sm text-gray-300 mb-8 border border-purple-500/20">
          <span className="w-2 h-2 bg-green-400 rounded-full"></span>
          <span>Advanced Threat Detection</span>
        </div>
        
        <h1 className="text-5xl md:text-6xl font-bold mb-6">
          <span className="text-white">Detect Fake Banking Apps</span>
          <br />
          <span className="bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
            Before They Do 
          </span>
          <span className="bg-gradient-to-r from-cyan-400 to-green-400 bg-clip-text text-transparent">
            Harm
          </span>
        </h1>
        
        <p className="text-xl text-gray-300 mb-8 max-w-2xl mx-auto leading-relaxed">
          Automatically identify and block malicious APKs disguised as legitimate banking apps.<br />
          Protect users from financial fraud and data compromise.
        </p>
        
        <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-6">
          <button className="flex items-center space-x-2 px-8 py-3 bg-gradient-to-r from-purple-500 to-pink-500 text-white rounded-lg font-medium hover:from-purple-600 hover:to-pink-600 transition-all duration-200 shadow-lg hover:shadow-purple-500/25"
            onClick={() => {
          document.getElementById('scan-section')?.scrollIntoView({ 
            behavior: 'smooth' 
          });
        }}
          >
            <span>Scan APK Now</span>
            <ArrowRight className="w-4 h-4" />
          </button>
          <button className="flex items-center space-x-2 px-8 py-3 bg-black/20 text-white rounded-lg font-medium hover:bg-black/30 transition-all duration-200 border border-gray-700">
            <Play className="w-4 h-4" />
            <span>Learn More</span>
          </button>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;