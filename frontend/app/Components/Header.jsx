"use client"
import React from 'react';
import { Shield } from 'lucide-react';

const Header = () => {
  return (
    <header className="flex items-center justify-between px-6 py-4 bg-black/10 backdrop-blur-sm">
      <div className="flex items-center space-x-2">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <span className="text-xl font-bold text-white">BankShield</span>
      </div>
      
      <button 
        onClick={() => {
          document.getElementById('scan-section')?.scrollIntoView({ 
            behavior: 'smooth' 
          });
        }}
        className="px-6 py-2 bg-gradient-to-r from-purple-500 to-pink-500 text-white rounded-lg font-medium hover:from-purple-600 hover:to-pink-600 transition-all duration-200"
      >
        Get Started
      </button>
    </header>
  );
};

export default Header;