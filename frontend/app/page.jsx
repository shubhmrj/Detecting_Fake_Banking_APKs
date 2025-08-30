import React from 'react';
import Header from './Components/Header';
import HeroSection from './Components/HeroSection';
import ScanSection from './Components/ScanSection';
import FeaturesSection from './Components/FeaturesSection';
import Footer from './Components/Footer';

const HomePage = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-indigo-900 to-purple-800">
      <Header />
      <main>
        <HeroSection />
        <ScanSection />
        <FeaturesSection />
      </main>
      <Footer />
    </div>
  );
};

export default HomePage;