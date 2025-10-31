# 🔧 Fix Vercel 404 Error

## Problem
Your Vercel deployment shows "404 NOT FOUND" because it doesn't know where your Next.js app is located.

## ✅ Solution: Configure Root Directory in Vercel

### Method 1: Redeploy with Correct Settings (RECOMMENDED)

1. **Go to Vercel Dashboard**
   - Visit: https://vercel.com/dashboard
   - Find your project: "detecting-fake-banking-ap-ks"

2. **Go to Project Settings**
   - Click on your project
   - Click "Settings" tab

3. **Update Root Directory**
   - Scroll to "Build & Development Settings"
   - Find "Root Directory"
   - Click "Edit"
   - Enter: `frontend`
   - Click "Save"

4. **Verify Other Settings**
   - **Framework Preset:** Next.js (should be auto-detected)
   - **Build Command:** `npm run build` (leave default)
   - **Output Directory:** `.next` (leave default)
   - **Install Command:** `npm install` (leave default)

5. **Add Environment Variable**
   - Still in Settings, go to "Environment Variables"
   - Click "Add New"
   - **Key:** `NEXT_PUBLIC_API_URL`
   - **Value:** `https://your-backend.onrender.com` (your Render backend URL)
   - Click "Save"

6. **Redeploy**
   - Go to "Deployments" tab
   - Click the three dots (...) on the latest deployment
   - Click "Redeploy"
   - Wait 2-3 minutes

7. **Test**
   - Visit: https://detecting-fake-banking-ap-ks.vercel.app
   - Should now show your app!

---

### Method 2: Delete and Reimport (If Method 1 Doesn't Work)

1. **Delete Current Project**
   - Go to Vercel Dashboard
   - Click your project
   - Settings → General → scroll to bottom
   - Click "Delete Project"
   - Confirm deletion

2. **Reimport with Correct Settings**
   - Click "Add New..." → "Project"
   - Select your GitHub repository
   - **IMPORTANT:** Before clicking Deploy:
     - Set **Root Directory** to: `frontend`
     - Add Environment Variable:
       - Key: `NEXT_PUBLIC_API_URL`
       - Value: Your Render backend URL
   - Click "Deploy"

3. **Wait for Deployment**
   - Should complete in 2-3 minutes
   - Visit your new URL

---

## 🎯 Quick Checklist

Make sure these settings are correct in Vercel:

- [ ] **Root Directory:** `frontend` ✅
- [ ] **Framework:** Next.js ✅
- [ ] **Build Command:** `npm run build` ✅
- [ ] **Output Directory:** `.next` ✅
- [ ] **Environment Variable:** `NEXT_PUBLIC_API_URL` set ✅

---

## 📸 Visual Guide

### Where to Find Root Directory Setting:

```
Vercel Dashboard
  → Your Project
    → Settings
      → General
        → Build & Development Settings
          → Root Directory: [Edit] → Enter "frontend"
```

### Where to Add Environment Variable:

```
Vercel Dashboard
  → Your Project
    → Settings
      → Environment Variables
        → Add New
          → Key: NEXT_PUBLIC_API_URL
          → Value: https://your-backend.onrender.com
```

---

## 🐛 Still Not Working?

### Check Build Logs

1. Go to Vercel Dashboard
2. Click "Deployments"
3. Click on the latest deployment
4. Check the build logs for errors

### Common Issues:

**Issue:** "Cannot find module 'next'"
- **Fix:** Root directory is wrong. Set to `frontend`

**Issue:** "Build failed"
- **Fix:** Check if `package.json` exists in `frontend/` folder
- **Fix:** Check if `npm install` completed successfully

**Issue:** "Page shows but API calls fail"
- **Fix:** Add `NEXT_PUBLIC_API_URL` environment variable
- **Fix:** Make sure backend is deployed and running

---

## 💡 Alternative: Use vercel.json (Advanced)

If you want to keep root at project level, delete the current `vercel.json` and create this one:

**File:** `vercel.json` (in project root)
```json
{
  "version": 2,
  "builds": [
    {
      "src": "frontend/package.json",
      "use": "@vercel/next"
    }
  ]
}
```

Then push to GitHub and Vercel will auto-redeploy.

---

## ✅ After Fix

Your app should be live at:
```
https://detecting-fake-banking-ap-ks.vercel.app
```

You should see:
- ✅ Banking APK Detection interface
- ✅ Upload button
- ✅ No 404 errors

---

## 🚀 Next Steps After Fix

1. Test APK upload functionality
2. Verify backend connection
3. Check if analysis works
4. Share the URL with your team!

---

**Need more help?** Check the build logs in Vercel dashboard for specific error messages.
