# ⚡ Quick Deploy Guide - Vercel + Render (100% FREE)

## 🎯 What You'll Get
- ✅ **Frontend:** Live on Vercel (https://your-app.vercel.app)
- ✅ **Backend:** Live on Render (https://your-backend.onrender.com)
- ✅ **Cost:** $0/month
- ✅ **Time:** 20 minutes

---

## 📋 Before You Start

### 1. Push Code to GitHub
```bash
cd "e:\Fake apk detection"
git init
git add .
git commit -m "Ready for deployment"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

---

## 🔧 Step 1: Deploy Backend (Render.com)

### A. Sign Up
1. Go to **https://render.com**
2. Click **"Get Started for Free"**
3. Sign up with **GitHub** (easiest)

### B. Create Web Service
1. Click **"New +"** → **"Web Service"**
2. Click **"Connect GitHub"** and authorize
3. Select repository: **"Fake apk detection"**
4. Click **"Connect"**

### C. Configure Settings

**Name:** `apk-detector-backend`  
**Region:** `Singapore` (closest to India)  
**Branch:** `main`  
**Root Directory:** `backend`  
**Environment:** `Python 3`  
**Build Command:** `pip install -r requirements.txt`  
**Start Command:** `python production_api.py`  
**Plan:** `Free`

### D. Add Environment Variables
Click **"Advanced"** → **"Add Environment Variable"**

Add these 3 variables:
```
FLASK_ENV = production
PYTHONUNBUFFERED = 1
PORT = 10000
```

### E. Deploy
1. Click **"Create Web Service"**
2. Wait 5-10 minutes (watch the logs)
3. When you see "Live ✓", copy your URL

**Your Backend URL:** `https://apk-detector-backend.onrender.com`

### F. Test Backend
Open in browser:
```
https://apk-detector-backend.onrender.com/api/health
```

Should show:
```json
{"status": "healthy", "model_loaded": true, ...}
```

✅ **Backend Done!**

---

## 🎨 Step 2: Deploy Frontend (Vercel)

### A. Sign Up
1. Go to **https://vercel.com**
2. Click **"Sign Up"**
3. Choose **"Continue with GitHub"**

### B. Import Project
1. Click **"Add New..."** → **"Project"**
2. Find **"Fake apk detection"**
3. Click **"Import"**

### C. Configure Settings

**Framework Preset:** `Next.js` (auto-detected)  
**Root Directory:** `frontend`  
**Build Command:** `npm run build` (auto)  
**Output Directory:** `.next` (auto)  
**Install Command:** `npm install` (auto)

### D. Add Environment Variable
Click **"Environment Variables"**

**Key:** `NEXT_PUBLIC_API_URL`  
**Value:** `https://apk-detector-backend.onrender.com` (your Render URL)

### E. Deploy
1. Click **"Deploy"**
2. Wait 2-3 minutes
3. When done, click **"Visit"**

**Your Frontend URL:** `https://your-project.vercel.app`

✅ **Frontend Done!**

---

## 🔗 Step 3: Connect Them (IMPORTANT!)

### Update Backend CORS

Your backend needs to accept requests from Vercel:

1. Go to **Render Dashboard**
2. Click your **backend service**
3. Click **"Environment"** tab
4. Click **"Add Environment Variable"**

**Key:** `CORS_ORIGINS`  
**Value:** `https://your-project.vercel.app` (your Vercel URL)

5. Click **"Save Changes"**
6. Service will auto-redeploy (2-3 minutes)

---

## ✅ Step 4: Test Your Live App

1. Open your Vercel URL: `https://your-project.vercel.app`
2. You should see the Banking APK Detection interface
3. Try uploading a test APK file
4. Check if analysis works

🎉 **Your app is LIVE and FREE!**

---

## 📱 Share Your App

**Public URL (share this):**
```
https://your-project.vercel.app
```

Anyone can access it worldwide!

---

## 🐛 Troubleshooting

### Backend Issues

**"Application failed to respond"**
- Check Render logs: Dashboard → Service → "Logs"
- Verify `requirements.txt` exists in `backend/` folder
- Check if all dependencies installed

**"Module not found"**
- Add missing package to `backend/requirements.txt`
- Redeploy on Render

**Backend is slow (30 sec first load)**
- Normal on free tier (spins down after 15 min)
- Subsequent requests are fast
- Upgrade to $7/month for always-on

### Frontend Issues

**"API connection failed"**
- Check `NEXT_PUBLIC_API_URL` is correct
- Visit backend `/api/health` to verify it's running
- Check browser console for errors

**"Build failed"**
- Check Vercel build logs
- Verify `package.json` exists in `frontend/` folder
- Ensure root directory is set to `frontend`

**CORS errors in browser**
- Add your Vercel URL to backend `CORS_ORIGINS`
- Redeploy backend after adding

---

## 💡 Pro Tips

### 1. Auto-Deploy on Git Push
Both platforms auto-deploy when you push to GitHub:
```bash
git add .
git commit -m "Update feature"
git push
```
- Vercel deploys automatically
- Render deploys automatically

### 2. Custom Domain (Optional)
**On Vercel:**
- Settings → Domains → Add your domain
- Free SSL included

### 3. Keep Backend Awake
Use **UptimeRobot** (free) to ping every 10 minutes:
- Sign up at https://uptimerobot.com
- Add monitor: `https://your-backend.onrender.com/api/health`
- Interval: 10 minutes

### 4. View Logs
**Render:** Dashboard → Service → "Logs"  
**Vercel:** Dashboard → Project → "Deployments" → Click deployment → "Logs"

---

## 📊 What You Get (Free Tier)

### Vercel
- ✅ Unlimited bandwidth
- ✅ Unlimited deployments
- ✅ Automatic HTTPS
- ✅ Custom domains
- ✅ 100 GB-hours/month

### Render
- ✅ 750 hours/month (24/7 uptime)
- ✅ 512 MB RAM
- ✅ Automatic HTTPS
- ✅ 100 GB bandwidth/month
- ⚠️ Spins down after 15 min (cold start ~30 sec)

**Perfect for demos and production use!**

---

## 🎯 Checklist

- [ ] Code pushed to GitHub
- [ ] Signed up on Render.com
- [ ] Backend deployed on Render
- [ ] Backend URL copied
- [ ] Tested `/api/health` endpoint
- [ ] Signed up on Vercel
- [ ] Frontend deployed on Vercel
- [ ] Added `NEXT_PUBLIC_API_URL` environment variable
- [ ] Added `CORS_ORIGINS` to backend
- [ ] Tested frontend upload feature
- [ ] Shared live URL with team

---

## 🚀 Your Live URLs

**Frontend (Share this!):**
```
https://_____________________.vercel.app
```

**Backend API:**
```
https://_____________________.onrender.com
```

---

## 📞 Need Help?

Read the full guide: **DEPLOYMENT_GUIDE_VERCEL_RENDER.md**

**Common URLs:**
- Render Dashboard: https://dashboard.render.com
- Vercel Dashboard: https://vercel.com/dashboard
- GitHub: https://github.com

---

**Deployment Complete! 🎉**
