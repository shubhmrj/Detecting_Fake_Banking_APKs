import React from 'react';
import { Shield, Users, Activity, Lock, Brain, Flag } from 'lucide-react';

const FeaturesSection = () => {
  const features = [
    {
      icon: <Shield className="w-6 h-6" />,
      title: "Static APK Analysis",
      description: "Scan app permissions, metadata, and manifest file to detect abnormal patterns.",
      bgColor: "bg-orange-500"
    },
    {
      icon: <Users className="w-6 h-6" />,
      title: "Permission Profiling", 
      description: "Compare permission sets with legitimate apps to identify red flags.",
      bgColor: "bg-pink-500"
    },
    {
      icon: <Activity className="w-6 h-6" />,
      title: "Dynamic Behavior Monitoring",
      description: "Emulate app behavior in a sandbox to detect fraud attempts in real-time.",
      bgColor: "bg-cyan-500"
    },
    {
      icon: <Lock className="w-6 h-6" />,
      title: "Certificate Verification",
      description: "Check if the signing certificate matches known authentic banking app publishers.",
      bgColor: "bg-green-500"
    },
    {
      icon: <Brain className="w-6 h-6" />,
      title: "ML-based Classification",
      description: "Trained models predict fake vs genuine banking apps with high accuracy.",
      bgColor: "bg-blue-500"
    },
    {
      icon: <Flag className="w-6 h-6" />,
      title: "Flag Suspicious APKs",
      description: "Instantly report unknown or suspicious apps for expert analysis.",
      bgColor: "bg-red-500"
    }
  ];

  return (
    <section className="py-20 px-6">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            <span className="text-white">Advanced Fake APK Detection</span>
            <br />
            <span className="bg-gradient-to-r from-green-400 to-cyan-400 bg-clip-text text-transparent">
              Features
            </span>
          </h2>
          <p className="text-gray-400 max-w-2xl mx-auto">
            Advanced security to shield your users from fake banking apps, credential 
            theft, and financial fraud.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <div 
              key={index}
              className="bg-black/20 backdrop-blur-sm border border-gray-700/50 rounded-xl p-6 hover:border-purple-500/50 transition-all duration-200 group"
            >
              <div className={`w-12 h-12 ${feature.bgColor} rounded-lg flex items-center justify-center mb-4 text-white group-hover:scale-110 transition-transform duration-200`}>
                {feature.icon}
              </div>
              <h3 className="text-xl font-semibold text-white mb-3">
                {feature.title}
              </h3>
              <p className="text-gray-400 leading-relaxed">
                {feature.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;