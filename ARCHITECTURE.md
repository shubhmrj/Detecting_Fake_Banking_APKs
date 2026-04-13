# AWS Deployment Architecture & Flow Diagrams

## 🏗️ Overall Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Your GitHub Repository                        │
│             (shubhmrj/Detecting_Fake_Banking_APKs)                  │
│                          Branch: secondstage                         │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               │ Push event
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      AWS CodePipeline                                │
│                  banking-apk-pipeline                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────┐     ┌──────────┐     ┌───────────┐                   │
│  │  Source  │────▶│  Build   │────▶│  Deploy   │                   │
│  │ (GitHub) │     │CodeBuild)│     │(Elastic   │                   │
│  └──────────┘     └──────────┘     │Beanstalk) │                   │
│                                     └───────────┘                    │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
                               │
                               │ Deployment
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   AWS Elastic Beanstalk                              │
│              banking-apk-backend Environment                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Auto Scaling Group (2-4 t3.medium EC2 instances)         │    │
│  │                                                             │    │
│  │  Each instance runs:                                       │    │
│  │  ├─ Flask API (production_api.py)                         │    │
│  │  ├─ ML Model (scikit-learn, XGBoost, TensorFlow)         │    │
│  │  ├─ androguard APK analyzer                              │    │
│  │  └─ Python virtualenv (Python 3.10)                      │    │
│  └────────────────────────────────────────────────────────────┘    │
│                               │                                      │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Application Load Balancer (ALB)                           │    │
│  │  ├─ Health check: /health endpoint                         │    │
│  │  ├─ HTTP (port 80) and HTTPS (port 443)                  │    │
│  │  └─ Route to healthy instances                            │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  CloudWatch Logs & Monitoring                              │    │
│  │  ├─ Application logs (/var/log/web.*)                     │    │
│  │  ├─ Nginx access logs                                      │    │
│  │  ├─ CPU, Memory, Network metrics                           │    │
│  │  └─ Health check results                                   │    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
        │                           │                        │
        │                           │                        │
        ▼                           ▼                        ▼
   ┌─────────┐              ┌─────────┐            ┌──────────────┐
   │  Users  │              │Admins   │            │Monitoring    │
   │(Browser)│              │(Logs)   │            │(CloudWatch)  │
   └─────────┘              └─────────┘            └──────────────┘
```

---

## 📊 CI/CD Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ Developer                                                             │
│ ├─ Edit code (backend/ or frontend/)                                │
│ ├─ Commit changes: git commit -m "..."                             │
│ └─ Push to secondstage: git push origin secondstage                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ GitHub Event: Push detected on secondstage branch                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ CodePipeline: Source Stage                                          │
│ ├─ GitHub connection receives webhook                              │
│ ├─ Downloads code from github.com/shubhmrj/...                    │
│ ├─ Outputs artifact to S3 (banking-apk-detector-artifacts)        │
│ └─ Status: SUCCESS ✓                                               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ CodePipeline: Build Stage (using CodeBuild)                        │
│                                                                       │
│ CodeBuild Project: banking-apk-detector-build                      │
│ ├─ EC2 build environment (Amazon Linux 2, Python 3.11)            │
│ ├─ Executes: buildspec.yml                                        │
│ │  ├─ Phase: pre_build                                            │
│ │  │  ├─ pip install requirements.txt                            │
│ │  │  ├─ npm install (frontend)                                  │
│ │  │  └─ Install scikit-learn==1.3.0                            │
│ │  │                                                               │
│ │  ├─ Phase: build                                               │
│ │  │  ├─ npm run build (Next.js frontend)                       │
│ │  │  └─ Python linting/tests (optional)                        │
│ │  │                                                               │
│ │  └─ Phase: post_build                                          │
│ │     └─ Prepare artifacts                                       │
│ │                                                                   │
│ ├─ Artifacts uploaded to S3                                        │
│ └─ Status: SUCCESS ✓                                               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ CodePipeline: Deploy Stage (using Elastic Beanstalk)               │
│                                                                       │
│ ├─ Elastic Beanstalk downloads artifact from S3                    │
│ ├─ Deploys to environment: banking-apk-backend                     │
│ │  ├─ Processes .ebextensions/                                    │
│ │  │  ├─ 01_flask.config (Flask/WSGI settings)                  │
│ │  │  ├─ 02_dependencies.config (Python deps)                   │
│ │  │  ├─ 03_nginx.config (Reverse proxy)                        │
│ │  │  └─ 04_env_vars.config (Environment)                       │
│ │  │                                                               │
│ │  ├─ On each EC2 instance:                                       │
│ │  │  ├─ Downloads code and dependencies                         │
│ │  │  ├─ Creates/updates Python virtualenv                       │
│ │  │  ├─ Installs requirements.txt                               │
│ │  │  ├─ Runs post-deployment hooks                              │
│ │  │  └─ Restarts Flask/Nginx services                           │
│ │  │                                                               │
│ │  └─ Health checks (HTTP GET /health)                            │
│ │     ├─ If healthy: Mark instance as InService                  │
│ │     └─ If unhealthy: Terminate instance, launch new one        │
│ │                                                                   │
│ └─ Status: SUCCESS ✓                                               │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Application is LIVE!                                                 │
│                                                                       │
│ URL: https://banking-apk-backend.us-east-1.elasticbeanstalk.com   │
│                                                                       │
│ Users can now:                                                       │
│ ├─ Visit frontend (domain URL)                                      │
│ ├─ Upload APK files                                                 │
│ └─ Get ML predictions                                               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Auto-Scaling & Load Balancing

```
                    Users' Requests
                    from the Internet
                           │
                           ▼
                  ┌─────────────────┐
                  │   Route 53      │
                  │ (DNS Routing)   │
                  └────────┬────────┘
                           │
                           ▼
          ┌────────────────────────────────┐
          │  Application Load Balancer     │
          │  (Distributes traffic)         │
          │  ├─ HTTP (port 80)             │
          │  └─ HTTPS (port 443)           │
          └────────────────────────────────┘
          │              │              │
    ┌─────▼──┐    ┌─────▼──┐    ┌─────▼──┐
    │  EC2   │    │  EC2   │    │  EC2   │
    │Instance│    │Instance│    │Instance│
    │   #1   │    │   #2   │    │   #3   │
    │ (t3.md)│    │ (t3.md)│    │ (t3.md)│
    └────┬───┘    └────┬───┘    └────┬───┘
         │             │             │
         ├─ Flask API  ├─ Flask API  ├─ Flask API
         ├─ Models     ├─ Models     ├─ Models
         ├─ Workers    ├─ Workers    ├─ Workers
         └─ Logs       └─ Logs       └─ Logs
         
    Auto Scaling Group Configuration:
    ├─ Min capacity: 2 instances
    ├─ Max capacity: 4 instances
    ├─ Desired capacity: 2 instances
    ├─ Scale up if: CPU > 70% for 5 min
    └─ Scale down if: CPU < 30% for 5 min
```

---

## 📁 File Structure After Deployment

```
GitHub Repository (Local)
│
├─ backend/
│  ├─ .ebextensions/
│  │  ├─ 01_flask.config          ← Flask/WSGI config
│  │  ├─ 02_dependencies.config    ← Python deps setup
│  │  ├─ 03_nginx.config           ← Reverse proxy
│  │  └─ 04_env_vars.config        ← Environment vars
│  │
│  ├─ .platform/
│  │  └─ hooks/postdeploy/
│  │     └─ 01_post_deploy.sh      ← Post-deploy script
│  │
│  ├─ production_api.py            ← Flask app entry point
│  ├─ requirements.txt             ← Python dependencies
│  └─ models/
│     └─ banking_model_metadata.json
│
├─ frontend/
│  ├─ app/
│  │  ├─ page.jsx
│  │  ├─ layout.jsx
│  │  └─ Components/
│  │
│  ├─ public/
│  ├─ package.json
│  └─ next.config.mjs
│
├─ buildspec.yml                  ← CodeBuild config
├─ AWS_DEPLOYMENT_GUIDE.md        ← Detailed guide
├─ QUICK_START.md                 ← Simple 5-step guide
├─ DEPLOYMENT_STEPS.md            ← Step-by-step phases
├─ DEPLOYMENT_CHECKLIST.md        ← Verification checklist
├─ TROUBLESHOOTING.md             ← Common issues & fixes
└─ FRONTEND_DEPLOYMENT_GUIDE.md   ← Frontend deployment
```

---

## 🌐 Network & Security

```
┌──────────────────────────────────────────────────────────────────┐
│                          INTERNET                                 │
│                       (Public IP)                                 │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   AWS Elastic Beanstalk VPC                       │
│                   (banking-apk-backend)                           │
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Application Load Balancer (Public)                        │ │
│  │  ├─ Security Group: ALB-SG                                │ │
│  │  │  ├─ Inbound: 80/443 from 0.0.0.0/0                   │ │
│  │  │  └─ Outbound: All                                      │ │
│  │  └─ Health check: /health                                 │ │
│  └────────┬─────────────────────────────────────────────────┘ │
│           │                                                      │
│  ┌────────▼──────────────────────────────────────────────────┐ │
│  │  EC2 Instances (Private)                                  │ │
│  │  Security Group: EC2-SG                                   │ │
│  │  ├─ Inbound: 80 from ALB-SG                              │ │
│  │  ├─ Inbound: 22 (SSH) for debugging                      │ │
│  │  └─ Outbound: All (for external APIs)                    │ │
│  │                                                             │ │
│  │  ┌──────────────────────────────────────────────────────┐ │ │
│  │  │ Instance 1                                           │ │ │
│  │  │ ├─ Nginx (port 80)                                 │ │ │
│  │  │ ├─ Flask WSGI (unix socket)                        │ │ │
│  │  │ ├─ Python virtualenv                               │ │ │
│  │  │ └─ CloudWatch agent (logging)                      │ │ │
│  │  └──────────────────────────────────────────────────────┘ │ │
│  │                                                             │ │
│  │  [Instance 2, 3, 4... similar]                            │ │
│  └──────────────────────────────────────────────────────────┘ │
│                           │                                     │
│  ┌────────────────────────▼──────────────────────────────────┐ │
│  │  Optional: RDS Database (if using one)                   │ │
│  │  Security Group: RDS-SG                                  │ │
│  │  ├─ Inbound: 3306 from EC2-SG                           │ │
│  │  └─ Encrypted at rest: Yes                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## 📊 Performance & Monitoring

```
Application Running
        │
    ┌───▼───────────┬──────────────┬──────────────┐
    │               │              │              │
    ▼               ▼              ▼              ▼
CloudWatch      Application      Nginx          System
Metrics         Logs             Logs           Metrics
    │               │              │              │
    └───┬───────────┴──────────────┴──────────────┘
        │
        ▼
┌─────────────────────────────────────────────┐
│        CloudWatch Dashboard                  │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │   CPU %  │  │ Memory % │  │   Disk   │ │
│  │   45%    │  │   62%    │  │  45GB    │ │
│  └──────────┘  └──────────┘  └──────────┘ │
│                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │ Requests │  │ Latency  │  │  Errors  │ │
│  │  1250/s  │  │  245ms   │  │   0.1%   │ │
│  └──────────┘  └──────────┘  └──────────┘ │
│                                              │
│  ┌──────────────────────────────────────┐  │
│  │  Recent Errors & Warnings            │  │
│  │  • 2024-04-13 15:30: Deploy success  │  │
│  │  • 2024-04-13 10:15: Auto-scaled +1  │  │
│  │  • 2024-04-12 23:45: No errors       │  │
│  └──────────────────────────────────────┘  │
│                                              │
└─────────────────────────────────────────────┘
```

---

## 💾 Data & Artifacts Flow

```
┌─────────────────────────────────┐
│  GitHub Repository              │
│  (Source Code)                  │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  CodeBuild                      │
│  (Compilation & Testing)        │
│                                 │
│  ├─ pip install deps            │
│  ├─ npm install                 │
│  ├─ npm run build (frontend)    │
│  └─ Run tests (optional)        │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  S3 Bucket                      │
│  (Artifact Storage)             │
│                                 │
│  banking-apk-detector-          │
│  artifacts-<account>            │
│                                 │
│  └─ built-app-<timestamp>.zip   │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  Elastic Beanstalk              │
│  (Deployment)                   │
│                                 │
│  ├─ Download artifact           │
│  ├─ Extract to /var/app         │
│  ├─ Install dependencies        │
│  └─ Restart services            │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│  EC2 Instances                  │
│  (Running Production App)       │
│                                 │
│  ├─ /var/app/current/           │
│  │  ├─ backend/                │
│  │  ├─ frontend/               │
│  │  └─ ...                     │
│  │                              │
│  └─ Logs → CloudWatch           │
└─────────────────────────────────┘
```

---

## 🔄 Update Lifecycle

```
Developer makes code change
        │
        ▼
git push origin secondstage
        │
        ▼
GitHub webhook → CodePipeline
        │
        ▼
Pipeline Status: RUNNING
        │
    ┌───▼────┬────────┬─────────┐
    │        │        │         │
    ▼        ▼        ▼         ▼
  Source  Build   Deploy    Complete
    │        │        │         │
    ✓        ✓        ✓         ✓
          
  (5sec)  (5min)   (5min)    (15min)
                   
        Old instances
        terminate
             ├─
             │
        New instances
        with latest code
        start serving traffic
        
        ↓
        
Zero downtime! Users don't notice!
```

---

This architecture provides:

✅ **High Availability** - Load balancing across multiple instances
✅ **Auto Scaling** - Handles traffic spikes automatically
✅ **CI/CD** - Automated build and deployment
✅ **Monitoring** - Real-time logs and metrics in CloudWatch
✅ **Security** - VPC, Security Groups, and optional HTTPS/HSTS
✅ **Cost Efficient** - Pay only for what you use (auto-scaling)
✅ **Fault Tolerance** - Automatic instance replacement if unhealthy

