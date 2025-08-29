// Frontend JavaScript for Fake Banking APK Detection System
const API_BASE_URL = 'http://localhost:5000/api';

// Global variables
let currentFile = null;
let riskChart = null;

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    loadDashboardData();
    loadHistory();
});

// Event Listeners
function initializeEventListeners() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const scanUrlBtn = document.getElementById('scanUrlBtn');

    // File upload
    uploadArea.addEventListener('click', () => fileInput.click());
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('drop', handleFileDrop);
    fileInput.addEventListener('change', handleFileSelect);
    analyzeBtn.addEventListener('click', analyzeAPK);
    scanUrlBtn.addEventListener('click', scanURL);
}

// File handling
function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('dragover');
}

function handleFileDrop(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFile(files[0]);
    }
}

function handleFileSelect(e) {
    if (e.target.files.length > 0) {
        handleFile(e.target.files[0]);
    }
}

function handleFile(file) {
    if (!file.name.toLowerCase().endsWith('.apk')) {
        showAlert('Please select an APK file', 'danger');
        return;
    }
    
    currentFile = file;
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = `(${formatFileSize(file.size)})`;
    document.getElementById('fileInfo').style.display = 'block';
    document.getElementById('analyzeBtn').disabled = false;
}

// API calls
async function analyzeAPK() {
    if (!currentFile) return;
    
    showLoading('Analyzing APK...');
    
    const formData = new FormData();
    formData.append('file', currentFile);
    
    try {
        const response = await axios.post(`${API_BASE_URL}/analyze`, formData);
        hideLoading();
        showResults(response.data);
        loadHistory();
        loadDashboardData();
    } catch (error) {
        hideLoading();
        showAlert('Analysis failed: ' + error.message, 'danger');
    }
}

async function scanURL() {
    const url = document.getElementById('urlInput').value;
    if (!url) {
        showAlert('Please enter a URL', 'warning');
        return;
    }
    
    showLoading('Scanning URL...');
    
    try {
        const response = await axios.post(`${API_BASE_URL}/scan-url`, { url });
        hideLoading();
        showURLResults(response.data);
    } catch (error) {
        hideLoading();
        showAlert('URL scan failed: ' + error.message, 'danger');
    }
}

// Results display
function showResults(data) {
    const analysis = data.analysis;
    const riskLevel = analysis.risk_level || 'UNKNOWN';
    const riskScore = analysis.risk_score || 0;
    
    const resultsHTML = `
        <div class="analysis-result">
            <div class="row">
                <div class="col-md-4 text-center">
                    <div class="risk-score-circle score-${riskLevel.toLowerCase()}">
                        ${riskScore}%
                    </div>
                    <span class="risk-badge risk-${riskLevel.toLowerCase()}">${riskLevel} Risk</span>
                </div>
                <div class="col-md-8">
                    <h5>${analysis.app_name}</h5>
                    <p><strong>Package:</strong> ${analysis.package_name}</p>
                    <p><strong>Version:</strong> ${analysis.version_name}</p>
                    <p><strong>Permissions:</strong> ${analysis.permission_count}</p>
                    <p><strong>Suspicious:</strong> ${analysis.is_suspicious ? 'Yes' : 'No'}</p>
                </div>
            </div>
            
            ${analysis.suspicious_permissions.length > 0 ? `
                <div class="mt-3">
                    <h6>Suspicious Permissions:</h6>
                    <div class="permission-list">
                        ${analysis.suspicious_permissions.map(perm => 
                            `<div class="permission-item suspicious">${perm}</div>`
                        ).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
    
    document.getElementById('resultsContent').innerHTML = resultsHTML;
    new bootstrap.Modal(document.getElementById('resultsModal')).show();
}

// Dashboard functions
async function loadDashboardData() {
    try {
        const response = await axios.get(`${API_BASE_URL}/statistics`);
        const stats = response.data.statistics;
        
        document.getElementById('totalAnalyses').textContent = stats.total_analyses;
        document.getElementById('suspiciousCount').textContent = stats.suspicious_count;
        document.getElementById('legitimateCount').textContent = stats.legitimate_count;
        
        const detectionRate = stats.total_analyses > 0 ? 
            Math.round((stats.suspicious_count / stats.total_analyses) * 100) : 0;
        document.getElementById('detectionRate').textContent = detectionRate + '%';
        
        updateRiskChart(stats.risk_distribution);
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
    }
}

// Navigation
function showSection(sectionName) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    document.getElementById(sectionName + '-section').classList.add('active');
    
    if (sectionName === 'dashboard') {
        loadDashboardData();
    } else if (sectionName === 'history') {
        loadHistory();
    }
}

// Utility functions
function showLoading(text) {
    document.getElementById('loadingText').textContent = text;
    new bootstrap.Modal(document.getElementById('loadingModal')).show();
}

function hideLoading() {
    bootstrap.Modal.getInstance(document.getElementById('loadingModal'))?.hide();
}

function showAlert(message, type) {
    // Simple alert implementation
    alert(message);
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function loadHistory() {
    try {
        const response = await axios.get(`${API_BASE_URL}/history`);
        const history = response.data.history;
        
        const tbody = document.getElementById('historyTableBody');
        tbody.innerHTML = history.map(item => `
            <tr>
                <td>${item.filename}</td>
                <td>${item.app_name}</td>
                <td><span class="badge bg-${item.risk_score >= 60 ? 'danger' : 'success'}">${item.risk_score}%</span></td>
                <td>${item.is_suspicious ? '<span class="badge bg-danger">Suspicious</span>' : '<span class="badge bg-success">Safe</span>'}</td>
                <td>${new Date(item.timestamp).toLocaleDateString()}</td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to load history:', error);
    }
}

function updateRiskChart(riskData) {
    const ctx = document.getElementById('riskChart');
    if (!ctx) return;
    
    if (riskChart) {
        riskChart.destroy();
    }
    
    riskChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(riskData),
            datasets: [{
                data: Object.values(riskData),
                backgroundColor: ['#28a745', '#17a2b8', '#ffc107', '#fd7e14', '#dc3545']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function showURLResults(data) {
    const analysis = data.analysis;
    const resultsHTML = `
        <div class="analysis-result">
            <h5>URL Analysis Results</h5>
            <p><strong>URL:</strong> ${analysis.url}</p>
            <p><strong>Risk Score:</strong> ${analysis.risk_score}%</p>
            <p><strong>Risk Level:</strong> <span class="risk-badge risk-${analysis.risk_level.toLowerCase()}">${analysis.risk_level}</span></p>
            <p><strong>Status:</strong> ${analysis.is_suspicious ? 'Suspicious' : 'Safe'}</p>
            
            ${analysis.risk_factors.length > 0 ? `
                <div class="mt-3">
                    <h6>Risk Factors:</h6>
                    <ul>
                        ${analysis.risk_factors.map(factor => `<li>${factor}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;
    
    document.getElementById('resultsContent').innerHTML = resultsHTML;
    new bootstrap.Modal(document.getElementById('resultsModal')).show();
}
