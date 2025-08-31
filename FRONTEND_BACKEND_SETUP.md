# Frontend-Backend Separate Setup Guide

This guide explains how to run the frontend and backend as separate processes for the Banking APK Detection System.

## Backend Setup (Flask API)

### 1. Navigate to Backend Directory
```bash
cd backend
```

### 2. Install Python Dependencies
```bash
pip install flask flask-cors androguard scikit-learn pandas numpy joblib cryptography
```

### 3. Start Backend Server
```bash
python enhanced_app.py
```

The backend API will be available at: `http://localhost:5000`

### Backend Endpoints:
- `GET /api/health` - Health check
- `POST /api/analyze` - Upload and analyze APK files
- `POST /api/scan-url` - Scan APK from URL
- `GET /api/history` - Get analysis history
- `GET /api/statistics` - Get system statistics

## Frontend Setup (Next.js)

### 1. Navigate to Frontend Directory
```bash
cd frontend
```

### 2. Install Node.js Dependencies
```bash
npm install
```

### 3. Start Frontend Development Server
```bash
npm run dev
```

The frontend will be available at: `http://localhost:3000`

## Testing the Connection

1. **Start Backend First**: Run `python enhanced_app.py` in the backend directory
2. **Start Frontend**: Run `npm run dev` in the frontend directory
3. **Open Browser**: Navigate to `http://localhost:3000`
4. **Test Upload**: Try uploading an APK file through the web interface

## CORS Configuration

The backend is already configured with CORS to allow requests from the frontend:
```python
from flask_cors import CORS
app = Flask(__name__)
CORS(app)  # Allows all origins
```

## Troubleshooting

### Backend Issues:
- **Port 5000 in use**: Change port in `enhanced_app.py` line 417
- **Missing dependencies**: Install required Python packages
- **Database errors**: Check if `data/` directory exists

### Frontend Issues:
- **Port 3000 in use**: Next.js will automatically use next available port
- **API connection failed**: Ensure backend is running on `http://localhost:5000`
- **Build errors**: Check if all dependencies are installed with `npm install`

### Connection Issues:
- **CORS errors**: Backend has CORS enabled, but check browser console
- **Network errors**: Verify both services are running on correct ports
- **File upload fails**: Check file size limits and APK file format

## Production Deployment

For production deployment:
1. Build frontend: `npm run build && npm run start`
2. Configure backend for production environment
3. Set up reverse proxy (nginx) if needed
4. Configure proper CORS origins for security
