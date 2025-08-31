"use client"
import React, { useState } from 'react';
import { Upload, Search, Plus, Send } from 'lucide-react';

const ScanSection = () => {
  const [activeTab, setActiveTab] = useState('file'); 
  const [dragActive, setDragActive] = useState(false);
  const [urlInput, setUrlInput] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setDragActive(false);
    setUrlInput('');
  };

  const handleFileUpload = async (file) => {
    if (!file || !file.name.endsWith('.apk')) {
      alert('Please select a valid APK file');
      return;
    }

    setIsAnalyzing(true);
    setAnalysisResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:5000/api/analyze', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();
      
      if (result.status === 'success') {
        setAnalysisResult(result);
      } else {
        setAnalysisResult({ 
          status: 'error', 
          error: result.error || 'Analysis failed',
          filename: file.name 
        });
      }
    } catch (error) {
      setAnalysisResult({ 
        status: 'error', 
        error: 'Failed to connect to backend API. Make sure the backend server is running on http://localhost:5000',
        filename: file.name 
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleUrlScan = () => {
    if (urlInput.trim()) {
      console.log('Scanning URL:', urlInput);
      // Add your URL scanning logic here
    }
  };

  return (
    <section id="scan-section" className="py-16 px-6">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-12">
          <p className="text-gray-400 mb-8 max-w-2xl mx-auto">
            Identify and stop malicious mobile apps posing as legitimate banking applications using certificate 
            verification, behavioral analysis, and AI-powered classification.
          </p>
          
          <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-6">
            <button 
              onClick={() => handleTabChange('file')}
              className={`flex items-center space-x-2 px-6 py-3 rounded-lg font-medium transition-all duration-200 ${
                activeTab === 'file' 
                  ? 'bg-gradient-to-r from-purple-500 to-pink-500 text-white shadow-lg' 
                  : 'bg-gray-700 text-white hover:bg-gray-600'
              }`}
            >
              <Upload className="w-4 h-4" />
              <span>Scan a file</span>
              {activeTab === 'file' && <div className="w-2 h-2 bg-green-400 rounded-full"></div>}
            </button>
            <button 
              onClick={() => handleTabChange('url')}
              className={`flex items-center space-x-2 px-6 py-3 rounded-lg font-medium transition-all duration-200 ${
                activeTab === 'url' 
                  ? 'bg-gradient-to-r from-purple-500 to-pink-500 text-white shadow-lg' 
                  : 'bg-gray-700 text-white hover:bg-gray-600'
              }`}
            >
              <Search className="w-4 h-4" />
              <span>Search a URL</span>
              {activeTab === 'url' && <div className="w-2 h-2 bg-green-400 rounded-full"></div>}
            </button>
          </div>
        </div>

        <div className="text-center mb-8">
          <h2 className="text-4xl font-bold text-white mb-6">Scan an APK</h2>
        </div>

        {/* File Upload Interface */}
        {activeTab === 'file' && (
          <div 
            className={`relative border-2 border-dashed rounded-xl p-12 text-center transition-all duration-300 ${
              dragActive 
                ? 'border-purple-400 bg-purple-500/10 scale-105' 
                : 'border-gray-600 bg-black/20 hover:border-gray-500'
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={(e) => {
              e.preventDefault();
              setDragActive(false);
              const files = e.dataTransfer.files;
              if (files.length > 0) {
                handleFileUpload(files[0]);
              }
            }}
          >
            <div className="flex flex-col items-center space-y-4">
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center transition-all duration-200 ${
                dragActive ? 'bg-purple-600' : 'bg-gray-700'
              }`}>
                <Upload className={`w-6 h-6 transition-colors duration-200 ${
                  dragActive ? 'text-white' : 'text-gray-400'
                }`} />
              </div>
              <p className="text-gray-400">
                {dragActive ? 'Drop your APK file here' : 'Scan a file'}
              </p>
              <p className="text-sm text-gray-500">
                Drag and drop an APK file or click to browse
              </p>
              <input
                type="file"
                accept=".apk"
                onChange={(e) => {
                  if (e.target.files.length > 0) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
                className="hidden"
                id="file-upload"
              />
              <label
                htmlFor="file-upload"
                className="flex items-center space-x-2 px-6 py-2 bg-gradient-to-r from-purple-500 to-cyan-500 text-white rounded-lg font-medium hover:from-purple-600 hover:to-cyan-600 transition-all duration-200 shadow-lg hover:shadow-purple-500/25 cursor-pointer"
              >
                <Plus className="w-4 h-4" />
                <span>Add File</span>
              </label>
            </div>
          </div>
        )}

        {/* URL Search Interface */}
        {activeTab === 'url' && (
          <div className="relative border border-gray-600 rounded-xl p-8 bg-black/20 backdrop-blur-sm transition-all duration-300">
            <div className="flex flex-col sm:flex-row items-center space-y-4 sm:space-y-0 sm:space-x-4">
              <div className="flex-1 w-full">
                <input
                  type="url"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="Enter URL to scan..."
                  className="w-full px-6 py-4 bg-gray-800/50 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-purple-500 focus:ring-2 focus:ring-purple-500/20 transition-all duration-200"
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      handleUrlScan();
                    }
                  }}
                />
              </div>
              <button 
                onClick={handleUrlScan}
                disabled={!urlInput.trim()}
                className={`flex items-center space-x-2 px-6 py-4 rounded-lg font-medium transition-all duration-200 ${
                  urlInput.trim() 
                    ? 'bg-gradient-to-r from-purple-500 to-cyan-500 text-white hover:from-purple-600 hover:to-cyan-600 shadow-lg hover:shadow-purple-500/25' 
                    : 'bg-gray-600 text-gray-400 cursor-not-allowed'
                }`}
              >
                <Send className="w-4 h-4" />
                <span>Scan</span>
              </button>
            </div>
            <div className="mt-4 flex items-center space-x-2 text-sm text-gray-500">
              <Search className="w-4 h-4" />
              <span>Enter a complete URL (e.g., https://example.com/app.apk)</span>
            </div>
          </div>
        )}

        {/* Analysis Results */}
        {isAnalyzing && (
          <div className="mt-8 p-6 bg-blue-900/20 border border-blue-500/30 rounded-xl">
            <div className="flex items-center space-x-3">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-400"></div>
              <p className="text-blue-400">Analyzing APK file...</p>
            </div>
          </div>
        )}

        {analysisResult && (
          <div className="mt-8 p-6 bg-gray-900/50 border border-gray-600 rounded-xl">
            <h3 className="text-xl font-bold text-white mb-4">Analysis Results</h3>
            
            {analysisResult.status === 'error' ? (
              <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-lg">
                <p className="text-red-400 font-medium">Error: {analysisResult.error}</p>
                <p className="text-gray-400 text-sm mt-2">File: {analysisResult.filename}</p>
              </div>
            ) : (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 bg-gray-800/50 rounded-lg">
                    <h4 className="font-medium text-white mb-2">App Information</h4>
                    <p className="text-sm text-gray-300">Package: {analysisResult.analysis?.package_name}</p>
                    <p className="text-sm text-gray-300">App Name: {analysisResult.analysis?.app_name}</p>
                    <p className="text-sm text-gray-300">Version: {analysisResult.analysis?.version_name}</p>
                  </div>
                  
                  <div className="p-4 bg-gray-800/50 rounded-lg">
                    <h4 className="font-medium text-white mb-2">Security Status</h4>
                    <div className={`inline-block px-3 py-1 rounded-full text-sm font-medium ${
                      analysisResult.analysis?.is_suspicious 
                        ? 'bg-red-900/30 text-red-400 border border-red-500/30' 
                        : 'bg-green-900/30 text-green-400 border border-green-500/30'
                    }`}>
                      {analysisResult.analysis?.is_suspicious ? 'SUSPICIOUS' : 'LEGITIMATE'}
                    </div>
                    <p className="text-sm text-gray-300 mt-2">
                      Risk Score: {analysisResult.analysis?.security_analysis?.risk_score || 0}/100
                    </p>
                  </div>
                </div>

                <div className="p-4 bg-gray-800/50 rounded-lg">
                  <h4 className="font-medium text-white mb-2">Permissions Analysis</h4>
                  <p className="text-sm text-gray-300">Total Permissions: {analysisResult.analysis?.permission_count || 0}</p>
                  <p className="text-sm text-gray-300">Suspicious Permissions: {analysisResult.analysis?.suspicious_permissions?.length || 0}</p>
                  <p className="text-sm text-gray-300">Critical Permissions: {analysisResult.analysis?.critical_permissions?.length || 0}</p>
                </div>

                {analysisResult.analysis?.ml_prediction && (
                  <div className="p-4 bg-gray-800/50 rounded-lg">
                    <h4 className="font-medium text-white mb-2">ML Analysis</h4>
                    <p className="text-sm text-gray-300">
                      Prediction: {analysisResult.analysis.ml_prediction.prediction || 'N/A'}
                    </p>
                    <p className="text-sm text-gray-300">
                      Confidence: {Math.round((analysisResult.analysis.ml_prediction.confidence || 0) * 100)}%
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
};

export default ScanSection;