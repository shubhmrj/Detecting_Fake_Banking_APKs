# Step-by-Step AWS Deployment Instructions

## Phase 1: Local Preparation

### 1. Update Your Git Repository

```bash
cd d:\Detecting_Fake_Banking_APKs

# Add all new configuration files
git add AWS_DEPLOYMENT_GUIDE.md buildspec.yml
git add backend/.ebextensions/ backend/.platform/
git commit -m "Add AWS Elastic Beanstalk & CodePipeline configuration"
git push origin secondstage
```

### 2. Verify Directory Structure

Ensure this structure exists:
```
backend/
├── .ebextensions/
│   ├── 01_flask.config
│   ├── 02_dependencies.config
│   ├── 03_nginx.config
│   └── 04_env_vars.config
├── .platform/
│   └── hooks/
│       └── postdeploy/
│           └── 01_post_deploy.sh
├── production_api.py
├── requirements.txt
└── models/

buildspec.yml  (root level)
```

---

## Phase 2: AWS Account Setup

### 1. Create IAM Role for Elastic Beanstalk

```bash
# Using AWS Console:
1. Go to IAM → Roles → Create role
2. Select service: Elastic Beanstalk
3. Attach policy: AWSElasticBeanstalkFullAccess
4. Attach policy: AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy
5. Name: aws-elasticbeanstalk-service-role
```

### 2. Create IAM Role for EC2 Instances

```bash
# Using AWS Console:
1. Go to IAM → Roles → Create role
2. Select service: EC2
3. Attach policies:
   - AWSElasticBeanstalkWorkerTier
   - AWSElasticBeanstalkMulticontainerDocker
   - AWSElasticBeanstalkWebTier
   - CloudWatchLogsFullAccess (for logging)
4. Name: aws-elasticbeanstalk-ec2-role
```

### 3. Create S3 Bucket for Build Artifacts

```bash
# Using AWS Console:
1. Go to S3 → Create bucket
2. Name: banking-apk-detector-artifacts-<account-id>
3. Block all public access: Yes
4. Create bucket
```

---

## Phase 3: AWS CodePipeline Setup

### 1. Create GitHub Connection (for CodePipeline V2)

```bash
# Using AWS Console:
1. Go to CodePipeline → Connections
2. Click "Create connection"
3. Select GitHub (version 2)
4. Connection name: banking-github-connection
5. Click "Connect to GitHub"
6. Authorize AWS Connector for GitHub
7. Select repository: shubhmrj/Detecting_Fake_Banking_APKs
8. Click "Connect"
```

### 2. Create CodeBuild Project

```bash
# Using AWS Console:
1. Go to CodeBuild → Create build project
2. Project name: banking-apk-detector-build
3. Source:
   - Provider: GitHub
   - Repository: https://github.com/shubhmrj/Detecting_Fake_Banking_APKs
   - Source version: secondstage
4. Environment:
   - OS: Amazon Linux 2
   - Runtime: Python 3.11
   - Image: aws/codebuild/amazonlinux2-x86_64-standard:5.0
   - Service role: Create new
5. Buildspec: Use buildspec.yml from source
6. Logs:
   - CloudWatch Logs enabled
   - Log group: /aws/codebuild/banking-apk-detector
7. Create build project
```

### 3. Create Pipeline

```bash
# Using AWS Console:
1. Go to CodePipeline → Create pipeline
2. Pipeline name: banking-apk-pipeline
3. Service role: Create new service role
4. Source stage:
   - Provider: GitHub (v2)
   - Connection: banking-github-connection
   - Repository: shubhmrj/Detecting_Fake_Banking_APKs
   - Branch: secondstage
   - Trigger: Push in selected branches
5. Build stage:
   - Provider: CodeBuild
   - Project name: banking-apk-detector-build
6. Deploy stage:
   - Provider: AWS Elastic Beanstalk
   - Application name: banking-apk-detector
   - Environment name: banking-apk-backend
   - Input artifacts: CodeBuild output
7. Review and create
```

---

## Phase 4: AWS Elastic Beanstalk Setup

### 1. Create Elastic Beanstalk Application

```bash
# Using AWS Console:
1. Go to Elastic Beanstalk → Applications
2. Create application:
   - Application name: banking-apk-detector
   - Application tags: Add any relevant tags
```

### 2. Create Environment

```bash
# Using AWS Console:
1. Go to Application → Create environment
2. Environment tier: Web server tier
3. Environment name: banking-apk-backend
4. Domain: banking-apk-backend (optional, auto-generated)
5. Platform:
   - Platform type: Managed platform
   - Platform: Python 3.10
   - Branch: Python running on 64bit Amazon Linux 2
   - Version: Latest
6. Application code:
   - Choose: Sample application (will be updated by CodePipeline)
7. Configure more options:
   - Presets: High availability
   - Capacity:
     - Environment type: Load balanced
     - Auto Scaling group: Min=2, Max=4, Desired=2
     - Instance type: t3.medium
   - Load balancer:
     - Type: Application Load Balancer
     - Public IP: Enabled
   - Security:
     - EC2 key pair: Select your key pair
   - Software:
     - Environment properties:
       - FLASK_ENV: production
       - PYTHONUNBUFFERED: true
   - Monitoring:
     - CloudWatch detailed metrics: Enabled
     - Enhanced health reporting: Enabled
8. Create environment

Wait for environment to be ready (usually 5-10 minutes)
```

---

## Phase 5: Configure API and CORS

### 1. Update Your Flask API

Make sure your `production_api.py` includes:

```python
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'}), 200
```

### 2. Verify Frontend can reach Backend

In your frontend, update API endpoint:

```javascript
// In your frontend components
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 
                      'https://banking-apk-backend.elasticbeanstalk.com';

// Use it in API calls
fetch(`${API_BASE_URL}/api/endpoint`)
```

---

## Phase 6: Deploy!

### 1. Trigger Pipeline (Automatic or Manual)

```bash
# Option A: Automatic (any push to secondstage branch)
git push origin secondstage

# Option B: Manual trigger via AWS Console
# Go to CodePipeline → banking-apk-pipeline → Release change
```

### 2. Monitor Deployment

```bash
# Option A: Via AWS Console
# CodePipeline → Watch stages progress
# Elastic Beanstalk → Environment health

# Option B: Via EB CLI (if installed)
eb status
eb logs

# Option C: Via CodeBuild
# CodeBuild → Build projects → banking-apk-detector-build
# View build logs there
```

### 3. Check Deployment Status

```bash
# Using AWS Console:
1. Go to Elastic Beanstalk → Environments
2. Select: banking-apk-backend
3. Check "Health" (should be Green)
4. Check "Logs" for any errors
```

---

## Phase 7: Post-Deployment

### 1. Get Your Application URL

```bash
# Using AWS Console:
Elastic Beanstalk → banking-apk-backend → Domain
# URL format: banking-apk-backend.region.elasticbeanstalk.com
```

### 2. Test Your Application

```bash
# Test health endpoint
curl https://banking-apk-backend.region.elasticbeanstalk.com/health

# Test API endpoints
curl -X POST https://banking-apk-backend.region.elasticbeanstalk.com/api/analyze \
  -F "file=@test_apk.apk"
```

### 3. Configure Custom Domain (Optional)

```bash
# Using Route 53 or your DNS provider
1. Create CNAME record pointing to Elastic Beanstalk URL
2. Configure SSL certificate via ACM
3. Update ALB listener to use HTTPS
```

---

## Troubleshooting

### Issue: Deployment fails in CodeBuild

**Solution:**
1. Check CodeBuild logs: AWS Console → CodeBuild → Builds
2. Common issues:
   - Dependencies timeout: Increase timeout in CodeBuild settings
   - scikit-learn build fails: Already handled in buildspec.yml
   - Model file missing: Ensure models/ directory is committed

### Issue: Elastic Beanstalk shows Red Health

**Solution:**
1. SSH into instance: `eb ssh`
2. Check logs: `tail -f /var/log/eb-activity.log`
3. Check Flask logs: `tail -f /var/log/eb-docker/containers/*/eb-docker.log`

### Issue: Frontend can't reach backend API

**Solution:**
1. Check CORS headers are enabled in Flask
2. Update frontend API endpoint URL
3. Check Security Group allows traffic on port 80/443
4. Verify ALB is healthy

### Issue: Scikit-learn version mismatch

**Solution:**
- This is handled by 02_dependencies.config
- SSH into instance and verify: `python -c "import sklearn; print(sklearn.__version__)"`
- Should be: 1.3.0

---

## Cost Optimization

1. Use t3.medium for testing, t3.large for production
2. Configure auto-scaling policies
3. Set up CloudWatch alarms for cost monitoring
4. Consider Elastic Beanstalk reserved instances for production

---

## Next Steps

1. Enable HTTPS with AWS Certificate Manager
2. Set up CloudWatch dashboards
3. Configure auto-scaling policies
4. Set up backup strategies for persistent data
5. Implement CI/CD improvements (unit tests in CodeBuild)
