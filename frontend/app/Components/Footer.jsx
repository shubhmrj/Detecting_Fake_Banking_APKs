import React from 'react';
import { Shield, Twitter, Github, Linkedin, Mail } from 'lucide-react';

const Footer = () => {
  const footerSections = {
    Product: ['Features', 'Pricing', 'API', 'Documentation'],
    Company: ['About', 'Blog', 'Careers', 'Contact'],
    Resources: ['Help Center', 'Security', 'Status', 'Terms']
  };

  return (
    <footer className="py-16 px-6 border-t border-gray-800">
      <div className="max-w-6xl mx-auto">
        {/* Trusted by Section */}
        <div className="text-center mb-16">
          <h2 className="text-3xl font-bold mb-4">
            <span className="text-white">Trusted by </span>
            <span className="bg-gradient-to-r from-purple-400 to-cyan-400 bg-clip-text text-transparent">
              Security Professionals
            </span>
          </h2>
          <p className="text-gray-400 max-w-2xl mx-auto">
            Join a growing network committed to stopping fake banking applications before they spread.
          </p>
        </div>

      
        {/* Footer Links */}
        {/* <div className="">
          <div>
            <div className="flex items-center space-x-2 mb-6">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center">
                <Shield className="w-5 h-5 text-white" />
              </div>
              <span className="text-xl font-bold text-white">BankShield</span>
            </div>
            <p className="text-gray-400 mb-6 leading-relaxed">
              Advanced malware protection for the modern digital landscape. Secure your apps, URLs, and digital assets with confidence.
            </p>
            <div className="flex space-x-4">
              <div className="w-8 h-8 bg-gray-700 rounded-lg flex items-center justify-center hover:bg-gray-600 transition-colors cursor-pointer">
                <Twitter className="w-4 h-4 text-gray-400" />
              </div>
              <div className="w-8 h-8 bg-gray-700 rounded-lg flex items-center justify-center hover:bg-gray-600 transition-colors cursor-pointer">
                <Github className="w-4 h-4 text-gray-400" />
              </div>
              <div className="w-8 h-8 bg-gray-700 rounded-lg flex items-center justify-center hover:bg-gray-600 transition-colors cursor-pointer">
                <Linkedin className="w-4 h-4 text-gray-400" />
              </div>
              <div className="w-8 h-8 bg-gray-700 rounded-lg flex items-center justify-center hover:bg-gray-600 transition-colors cursor-pointer">
                <Mail className="w-4 h-4 text-gray-400" />
              </div>
            </div>
          </div>

          {Object.entries(footerSections).map(([title, links]) => (
            <div key={title}>
              <h3 className="text-white font-semibold mb-4">{title}</h3>
              <ul className="space-y-3">
                {links.map((link) => (
                  <li key={link}>
                    <a href="#" className="text-gray-400 hover:text-white transition-colors">
                      {link}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))} 
        </div> */}

        {/* Bottom */}
        <div className="pt-8 border-t border-gray-800 text-center">
          <p className="text-gray-400 text-sm">
            © {new Date().getFullYear()} BankShield. All rights reserved.
          </p>
          
        </div>
      </div>
    </footer>
  );
};

export default Footer;