# 🚀 Deploy AI-VulnScanner PRO Max to Render.com

## Quick Deployment Guide

Follow these steps to deploy your vulnerability scanner and get a **live URL** that anyone can access!

---

## 📋 Prerequisites

- ✅ GitHub account (you already have this)
- ✅ Project pushed to GitHub (done: https://github.com/Saurabhdoiphode/AI-VulnScanner-PRO-Max)

---

## 🔧 Step-by-Step Deployment

### Step 1: Create Render Account

1. Go to https://render.com
2. Click **"Get Started"** or **"Sign Up"**
3. Sign up with your **GitHub account** (easiest option)
4. Authorize Render to access your GitHub repositories

### Step 2: Create New Web Service

1. After logging in, click **"New +"** button (top right)
2. Select **"Web Service"**
3. Connect your GitHub repository:
   - Click **"Connect account"** if needed
   - Search for: `AI-VulnScanner-PRO-Max`
   - Click **"Connect"** next to your repository

### Step 3: Configure Service

Fill in these settings:

**Basic Settings:**
- **Name**: `ai-vulnscanner-pro-max` (or your choice)
- **Region**: Choose closest to you (e.g., Oregon, Frankfurt, Singapore)
- **Branch**: `main`
- **Root Directory**: Leave blank
- **Runtime**: `Python 3`

**Build & Deploy Settings:**
- **Build Command**: `bash build.sh`
- **Start Command**: `cd web_app && gunicorn app:app --bind 0.0.0.0:$PORT`

**Instance Type:**
- Select **"Free"** (this gives you free hosting!)

**Environment Variables:**
Click **"Add Environment Variable"** and add:
- Key: `FLASK_ENV`
- Value: `production`

### Step 4: Deploy!

1. Scroll down and click **"Create Web Service"**
2. Wait 2-3 minutes while Render builds and deploys
3. You'll see build logs - wait for "Deploy succeeded" message

### Step 5: Access Your Live Scanner! 🎉

Once deployed, you'll get a URL like:
```
https://ai-vulnscanner-pro-max.onrender.com
```

**Share this URL with anyone!** They can:
- ✅ Access your scanner from anywhere
- ✅ Run vulnerability scans
- ✅ Download reports
- ✅ No installation needed

---

## 📊 After Deployment

### Your Live Scanner Will:
- ✅ Auto-deploy when you push to GitHub
- ✅ Run 24/7 on Render's servers
- ✅ Handle multiple users simultaneously
- ✅ Work without Ollama (uses fallback analysis)

### Free Tier Limits:
- ⏱️ Spins down after 15 minutes of inactivity (first request takes 30s)
- 💾 750 hours/month free (enough for personal use)
- 🔄 Auto-restarts monthly

### To Keep Always Active (Optional):
Upgrade to paid plan ($7/month) for:
- ⚡ No spin-down
- 🚀 Faster performance
- 📈 More resources

---

## 🔄 Update Your Deployed App

Whenever you make changes:

```powershell
git add .
git commit -m "Updated scanner features"
git push origin main
```

Render will **automatically** re-deploy! No manual steps needed.

---

## 🆘 Troubleshooting

### Build Fails?
- Check build logs on Render dashboard
- Ensure `requirements-deploy.txt` has all dependencies
- Verify Python version in `runtime.txt`

### App Crashes?
- Check runtime logs on Render dashboard
- Ensure PORT environment variable is used
- Verify all imports work without local files

### Slow First Load?
- Normal on free tier (cold start)
- Upgrade to paid tier for instant response

---

## 🌐 Custom Domain (Optional)

Want `scanner.yourdomain.com` instead of `.onrender.com`?

1. Buy domain (Namecheap, GoDaddy, etc.)
2. Go to Render dashboard → Settings → Custom Domain
3. Add your domain
4. Update DNS records as shown
5. Wait for SSL certificate (automatic)

---

## 🎯 Alternative Deployment Options

If Render doesn't work for you:

### **Railway** (Free Tier Available)
- https://railway.app
- Similar to Render
- Better for hobby projects

### **Fly.io** (Free Tier)
- https://fly.io
- Good global coverage
- Requires Docker knowledge

### **PythonAnywhere** (Free Tier)
- https://www.pythonanywhere.com
- Easy Python hosting
- URL: `yourusername.pythonanywhere.com`

---

## 📧 Support

After deployment, your scanner is **live**! Users can access it anytime at your Render URL.

Questions? Issues? Open an issue on GitHub:
https://github.com/Saurabhdoiphode/AI-VulnScanner-PRO-Max/issues

---

**Happy Scanning! 🛡️**
