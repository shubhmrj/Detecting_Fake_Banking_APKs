# AWS Elastic Beanstalk & CodePipeline Deployment Guide

## 📋 Architecture Overview

```
GitHub Repository
    ↓
AWS CodePipeline
    ↓
AWS CodeBuild (Build)
    ↓
Deploy to Elastic Beanstalk
    ├── Backend (Flask API) - EC2 instances
    ├── Frontend (Next.js) - EC2 instances or S3 + CloudFront
    └── RDS (Optional for database)
```

---

## 🚀 Prerequisites

- AWS Account with appropriate IAM permissions
- AWS CLI configured locally
- GitHub personal access token
- Elastic Beanstalk CLI (EB CLI)

---

## Step 1: Setup AWS Elastic Beanstalk

### 1.1 Install EB CLI
```bash
pip install awsebcli
```

### 1.2 Initialize Elastic Beanstalk
```bash
cd d:\Detecting_Fake_Banking_APKs
eb init -p "Python 3.10" banking-apk-detector --region us-east-1
```

### 1.3 Create Application Environments
```bash
# Backend environment
eb create banking-apk-backend --instance-type t3.medium --envtype LoadBalanced

# Frontend environment  
eb create banking-apk-frontend --instance-type t3.medium --envtype LoadBalanced
```

---

## Step 2: Configure Your Application

### 2.1 Backend Configuration
- Add `.ebextensions/` folder with configuration files
- Update Flask to use environment variables
- Configure for production deployment

### 2.2 Frontend Configuration  
- Build Next.js for production
- Configure for static hosting or custom server

---

## Step 3: Setup AWS CodePipeline

### 3.1 In AWS Console:
1. Go to CodePipeline service
2. Create new pipeline: `banking-apk-pipeline`
3. Connect to GitHub repository (secondstage branch)
4. Add CodeBuild stage for compilation
5. Add Deploy stage pointing to Elastic Beanstalk

### 3.2 Pipeline Flow:
```
Source (GitHub) → Build (CodeBuild) → Deploy (Elastic Beanstalk)
```

---

## Step 4: Environment Variables

Set these in Elastic Beanstalk environment:

```
FLASK_ENV=production
FLASK_APP=production_api.py
PYTHONUNBUFFERED=true
SCIKIT_LEARN_VERSION=1.3.0
```

---

## Deployment Commands Reference

```bash
# Deploy backend
eb deploy banking-apk-backend

# Deploy frontend
eb deploy banking-apk-frontend

# Check environment status
eb status

# View logs
eb logs

# Open in browser
eb open
```

---

## Key Considerations

1. **scikit-learn Version**: Requires 1.3.0 - configure in .ebextensions
2. **Dependencies**: Large ML libraries may cause timeout - increase timeout in buildspec.yml
3. **Static Files**: Frontend static assets should go to S3 or be served by Nginx
4. **Database**: If needed, use RDS with connection strings in environment variables
5. **Cost**: Monitor EC2 instance usage and scale accordingly

---

## Troubleshooting

- Check logs: `eb logs`
- SSH into instance: `eb ssh`
- Monitor health: AWS Console → Elastic Beanstalk
- Review CodeBuild logs in AWS Console

