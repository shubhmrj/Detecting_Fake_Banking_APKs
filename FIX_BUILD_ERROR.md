# 🔧 Fix Vercel Build Error - Quick Guide

## The Problem
Your Build Command is set to `npm run dev` (development) instead of `npm run build` (production).

## ✅ Quick Fix (2 minutes)

### Step 1: Change Build Command

You're already in the right place! In the Vercel Settings:

1. **Find "Build Command"** (you can see it in your screenshot)
2. **Click the "Override" toggle** (turn it ON if not already)
3. **Change from:** `npm run dev`
4. **Change to:** `npm run build`
5. **Click "Save"** button at the bottom

### Step 2: Verify Other Settings

Make sure these are correct (they look good in your screenshot):

| Setting | Correct Value | Your Current Value |
|---------|---------------|-------------------|
| **Root Directory** | `frontend` | ✅ `frontend` |
| **Framework Preset** | Next.js | ✅ Next.js |
| **Build Command** | `npm run build` | ❌ `npm run dev` (CHANGE THIS) |
| **Output Directory** | `Next.js` (auto) | ✅ `Next.js` |
| **Install Command** | `npm install` | ✅ `npm install` |

### Step 3: Redeploy

1. Click "Save" at the bottom of the settings page
2. Go to **"Deployments"** tab (top menu)
3. Click the three dots (...) on the latest deployment
4. Click **"Redeploy"**
5. Wait 2-3 minutes for build to complete

### Step 4: Test

Visit: https://detecting-fake-banking-ap-ks.vercel.app

✅ Should work now!

---

## 🎯 What Each Command Does

- **`npm run dev`** → Development mode (hot reload, debugging)
  - ❌ Don't use for production deployment
  
- **`npm run build`** → Production build (optimized, minified)
  - ✅ Use for Vercel deployment

---

## 📋 Complete Settings Checklist

After making changes, your settings should be:

```
Root Directory: frontend
Framework: Next.js
Build Command: npm run build
Output Directory: Next.js (or .next)
Install Command: npm install
Node.js Version: 22.x (or 18.x)
```

---

## 🐛 If Build Still Fails

### Check Build Logs

1. Go to "Deployments" tab
2. Click on the failed deployment
3. Look for error messages in the logs

### Common Issues:

**Error: "Module not found"**
- Check if all dependencies are in `frontend/package.json`
- Try: `cd frontend && npm install` locally to test

**Error: "Build failed"**
- Check if `npm run build` works locally
- Run: `cd frontend && npm run build` on your computer

**Error: "Out of memory"**
- Your app might be too large for free tier
- Try optimizing dependencies

---

## 💡 Quick Test Locally

Before redeploying, test if build works:

```bash
cd frontend
npm install
npm run build
npm start
```

If this works locally, it should work on Vercel!

---

## ✅ After Fix

Your deployment should:
- ✅ Build successfully
- ✅ Show your Banking APK Detection interface
- ✅ No 404 errors
- ✅ All routes working

---

**Summary:** Change Build Command from `npm run dev` to `npm run build`, save, and redeploy!
