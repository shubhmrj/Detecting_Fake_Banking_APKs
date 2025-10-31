# 🚀 Deploy to Vercel (Frontend) + Render (Backend)

## Overview
- **Frontend (Next.js):** Vercel - FREE forever
- **Backend (Flask):** Render.com - FREE tier
- **Total Cost:** $0/month
- **Deployment Time:** 20 minutes

---

## 📋 Prerequisites

1. **GitHub Account** - Sign up at https://github.com
2. **Push Your Code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
   git push -u origin main
   ```

---

## 🔧 Part 1: Deploy Backend to Render.com

### Step 1: Sign Up
1. Go to https://render.com
2. Click "Get Started for Free"
3. Sign up with GitHub (recommended)

### Step 2: Create Web Service
1. Click "New +" → "Web Service"
2. Click "Connect GitHub" and authorize Render
3. Select your repository: `Fake apk detection`
4. Click "Connect"

### Step 3: Configure Backend
Fill in these settings:

| Setting | Value |
|---------|-------|
| **Name** | `apk-detector-backend` (or your choice) |
| **Region** | Singapore (closest to India) |
| **Branch** | `main` |
| **Root Directory** | `backend` |
| **Environment** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `python production_api.py` |
| **Plan** | `Free` |

### Step 4: Add Environment Variables
Click "Advanced" → "Add Environment Variable":

```
FLASK_ENV=production
PYTHONUNBUFFERED=1
PORT=5000
```

### Step 5: Deploy
1. Click "Create Web Service"
2. Wait 5-10 minutes for deployment
3. **Copy your backend URL:** `https://apk-detector-backend.onrender.com`

### Step 6: Test Backend
Open in browser:
```
https://apk-detector-backend.onrender.com/api/health
```

You should see:
```json
{
  "status": "healthy",
  "model_loaded": true,
  "timestamp": "...",
  "version": "production_v1.0"
}
```

✅ **Backend is live!**

---

## 🎨 Part 2: Deploy Frontend to Vercel

### Step 1: Sign Up
1. Go to https://vercel.com
2. Click "Sign Up"
3. Choose "Continue with GitHub"

### Step 2: Import Project
1. Click "Add New..." → "Project"
2. Find your repository: `Fake apk detection`
3. Click "Import"

### Step 3: Configure Frontend

| Setting | Value |
|---------|-------|
| **Framework Preset** | Next.js (auto-detected) |
| **Root Directory** | `frontend` |
| **Build Command** | `npm run build` (auto-filled) |
| **Output Directory** | `.next` (auto-filled) |
| **Install Command** | `npm install` (auto-filled) |

### Step 4: Add Environment Variable
Click "Environment Variables" and add:

**Key:** `NEXT_PUBLIC_API_URL`  
**Value:** `https://apk-detector-backend.onrender.com` (your Render backend URL)

### Step 5: Deploy
1. Click "Deploy"
2. Wait 2-3 minutes
3. **Copy your frontend URL:** `https://your-project.vercel.app`

### Step 6: Test Frontend
1. Open your Vercel URL in browser
2. You should see the Banking APK Detection interface
3. Try uploading an APK file

✅ **Frontend is live!**

---

## 🔗 Connect Frontend to Backend

### Update Backend CORS (Important!)

Your backend needs to allow requests from your Vercel domain.

1. Go to Render dashboard
2. Click on your backend service
3. Go to "Environment" tab
4. Add new environment variable:

```
CORS_ORIGINS=https://your-project.vercel.app
```

5. Click "Save Changes"
6. Service will automatically redeploy

---

## 🎯 Your Live URLs

After deployment, you'll have:

**Frontend (Public URL):**
```
https://mp-police-apk-detector.vercel.app
```

**Backend API:**
```
https://apk-detector-backend.onrender.com
```

**Share this frontend URL with anyone!** 🎉

---

## 📱 Update Frontend API URL (If Needed)

If you need to change the backend URL later:

### On Vercel:
1. Go to your project dashboard
2. Click "Settings" → "Environment Variables"
3. Edit `NEXT_PUBLIC_API_URL`
4. Click "Save"
5. Go to "Deployments" → Click "..." → "Redeploy"

---

## ⚙️ Important Configuration Updates

### Update production_api.py for Render

Make sure your backend listens on the PORT environment variable:

```python
if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
```

### Update CORS in production_api.py

```python
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=[
    "https://your-project.vercel.app",
    "http://localhost:3000"  # for local development
])
```

---

## 🐛 Troubleshooting

### Backend Issues

**Problem:** Backend not starting
- Check Render logs: Dashboard → Your Service → "Logs"
- Verify `requirements.txt` has all dependencies
- Check if `production_api.py` exists in `backend/` folder

**Problem:** "Module not found" error
- Add missing package to `requirements.txt`
- Redeploy on Render

**Problem:** Backend sleeps after 15 minutes
- This is normal on free tier
- First request after sleep takes ~30 seconds
- Upgrade to paid plan ($7/month) for always-on

### Frontend Issues

**Problem:** API connection failed
- Verify `NEXT_PUBLIC_API_URL` is set correctly
- Check backend is running (visit `/api/health`)
- Check browser console for CORS errors

**Problem:** Build failed on Vercel
- Check Vercel build logs
- Verify `package.json` is in `frontend/` folder
- Ensure all dependencies are listed

**Problem:** Environment variable not working
- Must start with `NEXT_PUBLIC_` for client-side access
- Redeploy after adding environment variables

---

## 💡 Pro Tips

### 1. Custom Domain (Optional)
**Vercel:**
- Settings → Domains → Add your domain
- Free SSL included

### 2. Keep Backend Awake
Free Render services sleep after 15 min. To prevent:
- Use a service like UptimeRobot (free) to ping your backend every 10 minutes
- Or upgrade to Render paid plan ($7/month)

### 3. Monitor Your App
**Vercel Analytics:**
- Free analytics included
- See visitor stats, performance

**Render Logs:**
- Real-time logs in dashboard
- Monitor errors and requests

### 4. Automatic Deployments
Both platforms auto-deploy when you push to GitHub:
```bash
git add .
git commit -m "Update feature"
git push
```
- Vercel: Deploys automatically
- Render: Deploys automatically

---

## 📊 Free Tier Limits

### Vercel (Frontend)
- ✅ Unlimited bandwidth
- ✅ Unlimited deployments
- ✅ 100 GB-hours compute/month
- ✅ Custom domains
- ✅ Automatic HTTPS

### Render (Backend)
- ✅ 750 hours/month (enough for 24/7)
- ✅ 512 MB RAM
- ✅ Automatic HTTPS
- ⚠️ Spins down after 15 min inactivity
- ⚠️ 100 GB bandwidth/month

**Perfect for demos and testing!**

---

## 🚀 Quick Deployment Checklist

- [ ] Code pushed to GitHub
- [ ] Signed up on Render.com
- [ ] Backend deployed on Render
- [ ] Backend URL copied
- [ ] Signed up on Vercel
- [ ] Frontend deployed on Vercel
- [ ] Environment variable `NEXT_PUBLIC_API_URL` set
- [ ] CORS configured on backend
- [ ] Tested `/api/health` endpoint
- [ ] Tested frontend upload feature
- [ ] Shared live URL!

---

## 🎉 You're Live!

Your Banking APK Detection System is now deployed and accessible worldwide!

**Next Steps:**
1. Test thoroughly with different APK files
2. Share the URL with MP Police team
3. Monitor logs for any issues
4. Consider upgrading if you need better performance

**Need help?** Check the troubleshooting section or Render/Vercel documentation.

---

**Deployment Date:** _______________  
**Frontend URL:** _______________  
**Backend URL:** _______________
