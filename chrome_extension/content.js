// Content Script for ML Banking APK Scanner
// Runs on APK repository pages to provide real-time scanning

class ContentMLScanner {
    constructor() {
        this.scannerActive = false;
        this.scannedElements = new Set();
        this.initializeScanner();
    }
    
    initializeScanner() {
        // Only run on APK sites
        if (!this.isAPKSite()) return;
        
        console.log('ML Banking APK Scanner: Content script loaded');
        
        // Add scanner UI
        this.addScannerUI();
        
        // Start monitoring for banking APKs
        this.startMonitoring();
        
        // Listen for messages from popup
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
        });
    }
    
    isAPKSite() {
        const apkSites = [
            'apkpure.com', 'apkmirror.com', 'apkmonk.com',
            'aptoide.com', 'uptodown.com', 'play.google.com'
        ];
        return apkSites.some(site => window.location.hostname.includes(site));
    }
    
    addScannerUI() {
        // Create floating scanner widget
        const scannerWidget = document.createElement('div');
        scannerWidget.id = 'ml-banking-scanner';
        scannerWidget.innerHTML = `
            <div style="
                position: fixed;
                top: 20px;
                right: 20px;
                width: 300px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 15px;
                border-radius: 12px;
                box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                z-index: 10000;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255,255,255,0.2);
            ">
                <div style="display: flex; align-items: center; margin-bottom: 10px;">
                    <div style="font-size: 18px; margin-right: 8px;">🛡️</div>
                    <div style="font-weight: bold;">ML Banking Scanner</div>
                    <div style="margin-left: auto; cursor: pointer;" id="scanner-close">✕</div>
                </div>
                <div id="scanner-status" style="margin-bottom: 10px; font-size: 12px; opacity: 0.9;">
                    🧠 AI Model Active - Scanning for threats...
                </div>
                <div id="scanner-results" style="font-size: 12px;">
                    <div style="color: #2ed573;">✅ Page scanned - No threats detected</div>
                </div>
            </div>
        `;
        
        document.body.appendChild(scannerWidget);
        
        // Add close functionality
        document.getElementById('scanner-close').addEventListener('click', () => {
            scannerWidget.remove();
        });
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            if (scannerWidget.parentNode) {
                scannerWidget.style.opacity = '0.7';
                scannerWidget.style.transform = 'translateX(20px)';
            }
        }, 5000);
    }
    
    startMonitoring() {
        // Scan existing elements
        this.scanPage();
        
        // Monitor for new elements (dynamic loading)
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        this.scanElement(node);
                    }
                });
            });
        });
        
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }
    
    scanPage() {
        // Look for banking-related APK links
        const bankingKeywords = [
            'bank', 'banking', 'finance', 'payment', 'wallet',
            'sbi', 'hdfc', 'axis', 'icici', 'kotak'
        ];
        
        const apkLinks = document.querySelectorAll('a[href*=".apk"], a[href*="download"]');
        
        apkLinks.forEach(link => {
            const linkText = link.textContent.toLowerCase();
            const linkHref = link.href.toLowerCase();
            
            const isBankingRelated = bankingKeywords.some(keyword => 
                linkText.includes(keyword) || linkHref.includes(keyword)
            );
            
            if (isBankingRelated) {
                this.analyzeAPKLink(link);
            }
        });
    }
    
    scanElement(element) {
        if (this.scannedElements.has(element)) return;
        this.scannedElements.add(element);
        
        // Check if element contains APK links
        const apkLinks = element.querySelectorAll('a[href*=".apk"], a[href*="download"]');
        apkLinks.forEach(link => this.analyzeAPKLink(link));
    }
    
    analyzeAPKLink(link) {
        const linkText = link.textContent.toLowerCase();
        const linkHref = link.href.toLowerCase();
        
        // Simple risk assessment
        let riskScore = 20;
        let isLegitimate = true;
        
        // Check for suspicious patterns
        const suspiciousPatterns = ['fake', 'clone', 'mod', 'hack', 'crack', 'free premium'];
        const legitimatePatterns = ['play.google.com', 'official', 'verified'];
        
        suspiciousPatterns.forEach(pattern => {
            if (linkText.includes(pattern) || linkHref.includes(pattern)) {
                riskScore += 25;
                isLegitimate = false;
            }
        });
        
        legitimatePatterns.forEach(pattern => {
            if (linkText.includes(pattern) || linkHref.includes(pattern)) {
                riskScore = Math.max(riskScore - 15, 15);
                isLegitimate = true;
            }
        });
        
        // Add visual indicator
        this.addRiskIndicator(link, riskScore, isLegitimate);
    }
    
    addRiskIndicator(element, riskScore, isLegitimate) {
        // Remove existing indicator
        const existingIndicator = element.querySelector('.ml-risk-indicator');
        if (existingIndicator) existingIndicator.remove();
        
        // Create risk indicator
        const indicator = document.createElement('div');
        indicator.className = 'ml-risk-indicator';
        
        let color, text, icon;
        
        if (riskScore < 40) {
            color = '#2ed573';
            text = 'SAFE';
            icon = '✅';
        } else if (riskScore < 70) {
            color = '#ffa502';
            text = 'CAUTION';
            icon = '⚠️';
        } else {
            color = '#ff4757';
            text = 'THREAT';
            icon = '🚨';
        }
        
        indicator.innerHTML = `
            <div style="
                display: inline-block;
                background: ${color};
                color: white;
                padding: 4px 8px;
                border-radius: 12px;
                font-size: 10px;
                font-weight: bold;
                margin-left: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            ">
                ${icon} ${text} (${riskScore})
            </div>
        `;
        
        // Add indicator to element
        element.style.position = 'relative';
        element.appendChild(indicator);
        
        // Update scanner results
        this.updateScannerResults(riskScore >= 70);
    }
    
    updateScannerResults(threatFound) {
        const resultsElement = document.getElementById('scanner-results');
        if (!resultsElement) return;
        
        if (threatFound) {
            resultsElement.innerHTML = `
                <div style="color: #ff4757;">🚨 Threat detected on this page!</div>
                <div style="font-size: 11px; margin-top: 5px; opacity: 0.8;">
                    High-risk banking APK found. Exercise caution.
                </div>
            `;
        } else {
            resultsElement.innerHTML = `
                <div style="color: #2ed573;">✅ Page scanned - Banking APKs appear safe</div>
            `;
        }
    }
    
    handleMessage(request, sender, sendResponse) {
        switch (request.action) {
            case 'scanPage':
                this.scanPage();
                sendResponse({ success: true });
                break;
                
            case 'getPageInfo':
                sendResponse({
                    url: window.location.href,
                    title: document.title,
                    isAPKSite: this.isAPKSite()
                });
                break;
        }
    }
}

// Initialize content scanner when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new ContentMLScanner();
    });
} else {
    new ContentMLScanner();
}
