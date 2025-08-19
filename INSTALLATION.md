# Installation Guide - ADZero Trust

This comprehensive installation guide will walk you through setting up ADZero Trust in your environment, from prerequisites to production deployment.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Prerequisites](#prerequisites)
3. [Installation Methods](#installation-methods)
4. [Configuration](#configuration)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)
7. [Upgrade Instructions](#upgrade-instructions)

## System Requirements

### Minimum Requirements

**Hardware**
- **CPU**: 2 cores, 2.4 GHz or higher
- **RAM**: 4 GB minimum, 8 GB recommended
- **Storage**: 10 GB free disk space
- **Network**: 100 Mbps network connection

**Software**
- **Operating System**: Windows Server 2016+ or Windows 10/11
- **PowerShell**: Version 5.1 or higher
- **Python**: Version 3.8 or higher
- **Node.js**: Version 16 or higher
- **Web Browser**: Chrome 90+, Firefox 88+, Edge 90+

### Recommended Requirements

**Hardware**
- **CPU**: 4 cores, 3.0 GHz or higher
- **RAM**: 16 GB or more
- **Storage**: 50 GB free disk space (SSD recommended)
- **Network**: 1 Gbps network connection

**Software**
- **Operating System**: Windows Server 2022 or Windows 11
- **PowerShell**: Version 7.x (latest)
- **Python**: Version 3.11 (latest stable)
- **Node.js**: Version 18 (latest LTS)

## Prerequisites

### Active Directory Environment

ADZero Trust requires access to an Active Directory environment with appropriate permissions:

**Required Permissions**
- **Domain Admin** privileges (recommended for comprehensive assessment)
- **Enterprise Admin** privileges (for multi-domain environments)
- **Read** access to all organizational units
- **Audit** privileges for security log analysis

**Alternative Minimum Permissions**
If Domain Admin privileges are not available, the following minimum permissions are required:
- **Account Operators** group membership
- **Read** access to Active Directory schema
- **List Contents** and **Read All Properties** on all OUs
- **Generate Security Audits** user right

### PowerShell Configuration

1. **Enable PowerShell Execution Policy**
   ```powershell
   # Run as Administrator
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
   ```

2. **Install Active Directory Module**
   ```powershell
   # On Windows Server
   Install-WindowsFeature -Name RSAT-AD-PowerShell
   
   # On Windows 10/11
   Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
   ```

3. **Verify Active Directory Module**
   ```powershell
   Import-Module ActiveDirectory
   Get-Module ActiveDirectory
   ```

### Python Environment

1. **Install Python 3.8+**
   - Download from [python.org](https://www.python.org/downloads/)
   - Ensure "Add Python to PATH" is selected during installation
   - Verify installation: `python --version`

2. **Install pip (if not included)**
   ```bash
   python -m ensurepip --upgrade
   ```

3. **Install virtualenv**
   ```bash
   pip install virtualenv
   ```

### Node.js Environment

1. **Install Node.js 16+**
   - Download from [nodejs.org](https://nodejs.org/)
   - Choose LTS version for stability
   - Verify installation: `node --version` and `npm --version`

2. **Install pnpm (optional but recommended)**
   ```bash
   npm install -g pnpm
   ```

## Installation Methods

### Method 1: Standard Installation (Recommended)

This is the recommended installation method for most users.

#### Step 1: Clone Repository

```bash
# Clone the repository
git clone https://github.com/moazzamjafri/adzero-trust.git
cd adzero-trust
```

#### Step 2: Backend Installation

```bash
# Navigate to backend directory
cd Backend/adzero_backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows
venv\Scripts\activate
# On Linux/Mac
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python src/init_db.py
```

#### Step 3: Frontend Installation

```bash
# Navigate to frontend directory
cd ../../Frontend/adzero-dashboard

# Install dependencies
npm install
# or with pnpm
pnpm install

# Build for production (optional)
npm run build
```

#### Step 4: PowerShell Module Setup

```powershell
# Navigate to PowerShell directory
cd PowerShell\Modules

# Import all modules
Get-ChildItem -Path . -Filter "*.ps1" | ForEach-Object {
    Import-Module $_.FullName -Force
}

# Verify modules are loaded
Get-Module | Where-Object {$_.Name -like "*AD*"}
```

### Method 2: Docker Installation (Advanced)

For containerized deployment, use the provided Docker configuration.

#### Prerequisites
- Docker Desktop or Docker Engine
- Docker Compose

#### Installation Steps

```bash
# Clone repository
git clone https://github.com/moazzamjafri/adzero-trust.git
cd adzero-trust

# Build and start containers
docker-compose up -d

# Verify containers are running
docker-compose ps
```

#### Docker Configuration

The `docker-compose.yml` file includes:
- **Backend container**: Python Flask API
- **Frontend container**: React application served by nginx
- **Database container**: PostgreSQL for production use
- **Redis container**: For caching and session management

### Method 3: Development Installation

For developers contributing to the project.

#### Additional Prerequisites
- **Git** for version control
- **VS Code** or preferred IDE
- **Postman** for API testing

#### Development Setup

```bash
# Clone with development branch
git clone -b develop https://github.com/moazzamjafri/adzero-trust.git
cd adzero-trust

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Backend development setup
cd Backend/adzero_backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements-dev.txt

# Frontend development setup
cd ../../Frontend/adzero-dashboard
npm install
npm install -D @types/node @types/react @types/react-dom

# Start development servers
# Terminal 1 - Backend
cd Backend/adzero_backend
python src/main.py

# Terminal 2 - Frontend
cd Frontend/adzero-dashboard
npm run dev
```

## Configuration

### Backend Configuration

#### Environment Variables

Create a `.env` file in the `Backend/adzero_backend` directory:

```bash
# Database Configuration
DATABASE_URL=sqlite:///adzero_trust.db
# For PostgreSQL: postgresql://username:password@localhost:5432/adzero_trust

# Security Configuration
SECRET_KEY=your-very-secure-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here

# PowerShell Configuration
POWERSHELL_TIMEOUT=3600
POWERSHELL_EXECUTION_POLICY=RemoteSigned

# Assessment Configuration
MAX_ASSESSMENT_SIZE=100000
ASSESSMENT_RETENTION_DAYS=365
ENABLE_DETAILED_LOGGING=true

# API Configuration
API_HOST=0.0.0.0
API_PORT=5000
DEBUG=false

# Email Configuration (for notifications)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

#### Database Configuration

For SQLite (default):
```python
# config.py
SQLALCHEMY_DATABASE_URI = 'sqlite:///adzero_trust.db'
```

For PostgreSQL (production):
```python
# config.py
SQLALCHEMY_DATABASE_URI = 'postgresql://username:password@localhost:5432/adzero_trust'
```

#### Logging Configuration

```python
# logging_config.py
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
    },
    'handlers': {
        'default': {
            'level': 'INFO',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
        'file': {
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.FileHandler',
            'filename': 'adzero_trust.log',
        },
    },
    'loggers': {
        '': {
            'handlers': ['default', 'file'],
            'level': 'DEBUG',
            'propagate': False
        }
    }
}
```

### Frontend Configuration

#### Environment Variables

Create a `.env` file in the `Frontend/adzero-dashboard` directory:

```bash
# API Configuration
REACT_APP_API_BASE_URL=http://localhost:5000
REACT_APP_API_TIMEOUT=30000

# Application Configuration
REACT_APP_ENVIRONMENT=production
REACT_APP_VERSION=1.0.0
REACT_APP_BUILD_DATE=2024-01-01

# Feature Flags
REACT_APP_ENABLE_ANALYTICS=true
REACT_APP_ENABLE_NOTIFICATIONS=true
REACT_APP_ENABLE_EXPORT=true

# UI Configuration
REACT_APP_THEME=light
REACT_APP_LANGUAGE=en
REACT_APP_TIMEZONE=UTC
```

#### Build Configuration

For production builds, update `vite.config.js`:

```javascript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    minify: 'terser',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          ui: ['@radix-ui/react-dialog', '@radix-ui/react-dropdown-menu'],
          charts: ['recharts'],
        },
      },
    },
  },
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
    },
  },
})
```

### PowerShell Configuration

#### Module Configuration

Create a configuration file `PowerShell/Config/AssessmentConfig.ps1`:

```powershell
# Assessment Configuration
$Global:ADZeroTrustConfig = @{
    # General Settings
    MaxObjectsToProcess = 100000
    TimeoutMinutes = 60
    EnableVerboseLogging = $true
    
    # Identity Analysis Settings
    AnalyzeServiceAccounts = $true
    AnalyzePrivilegedAccounts = $true
    CheckPasswordPolicies = $true
    AnalyzeMFAStatus = $true
    
    # Permission Analysis Settings
    AnalyzeFilePermissions = $true
    AnalyzeSharePermissions = $true
    AnalyzeRegistryPermissions = $false
    MaxPermissionDepth = 5
    
    # Security Analysis Settings
    CheckGroupPolicies = $true
    AnalyzeAuditSettings = $true
    CheckEncryptionStatus = $true
    AnalyzeFirewallSettings = $true
    
    # Output Settings
    OutputFormat = "JSON"
    CompressOutput = $true
    IncludeRawData = $false
    
    # Domain Settings
    DefaultDomain = $env:USERDNSDOMAIN
    IncludeChildDomains = $true
    AnalyzeTrusts = $true
}
```

#### Execution Policy Configuration

```powershell
# Set execution policy for the current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# For enterprise deployment, use Group Policy to set execution policy
# Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell
# Turn on Script Execution: Allow local scripts and remote signed scripts
```

## Verification

### Backend Verification

1. **Test API Endpoints**
   ```bash
   # Activate virtual environment
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   
   # Start the backend
   python src/main.py
   
   # Test health endpoint
   curl http://localhost:5000/api/health
   ```

2. **Test Database Connection**
   ```python
   # Run in Python shell
   from src.models import db
   from src.main import app
   
   with app.app_context():
       db.create_all()
       print("Database connection successful!")
   ```

3. **Test PowerShell Integration**
   ```bash
   # Test PowerShell execution
   curl -X POST http://localhost:5000/api/powershell/test \
        -H "Content-Type: application/json" \
        -d '{"script": "Get-Date"}'
   ```

### Frontend Verification

1. **Development Server**
   ```bash
   # Start development server
   npm run dev
   
   # Access application
   # Open http://localhost:5173 in browser
   ```

2. **Production Build**
   ```bash
   # Build for production
   npm run build
   
   # Serve production build
   npm run preview
   
   # Access application
   # Open http://localhost:4173 in browser
   ```

3. **Component Testing**
   ```bash
   # Run component tests
   npm run test
   
   # Run with coverage
   npm run test:coverage
   ```

### PowerShell Verification

1. **Module Import Test**
   ```powershell
   # Test module imports
   Import-Module .\PowerShell\Modules\AD-InfoGatherer.ps1
   Get-Command -Module AD-InfoGatherer
   ```

2. **Active Directory Connectivity**
   ```powershell
   # Test AD connectivity
   Get-ADDomain
   Get-ADUser -Filter * -ResultSetSize 1
   ```

3. **Assessment Script Test**
   ```powershell
   # Run quick assessment test
   .\PowerShell\Scripts\Start-ADZeroTrustAssessment.ps1 -TestMode -Verbose
   ```

### Integration Verification

1. **End-to-End Test**
   - Start backend server
   - Start frontend development server
   - Create a new assessment in the UI
   - Verify PowerShell scripts execute
   - Check assessment results display

2. **API Integration Test**
   ```bash
   # Test full assessment workflow
   curl -X POST http://localhost:5000/api/assessments \
        -H "Content-Type: application/json" \
        -d '{
          "name": "Test Assessment",
          "domain": "test.local",
          "type": "quick"
        }'
   ```

## Troubleshooting

### Common Issues

#### PowerShell Execution Policy Error

**Error**: "cannot be loaded because running scripts is disabled on this system"

**Solution**:
```powershell
# Check current policy
Get-ExecutionPolicy -List

# Set policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# For system-wide (requires admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

#### Active Directory Module Not Found

**Error**: "The specified module 'ActiveDirectory' was not loaded"

**Solution**:
```powershell
# On Windows Server
Install-WindowsFeature -Name RSAT-AD-PowerShell

# On Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Verify installation
Get-WindowsCapability -Online -Name RSAT*
```

#### Python Virtual Environment Issues

**Error**: "venv command not found" or activation fails

**Solution**:
```bash
# Install virtualenv
pip install virtualenv

# Create environment with virtualenv
virtualenv venv

# Alternative: use python -m venv
python -m venv venv

# On Windows, if activation fails
venv\Scripts\activate.bat
```

#### Node.js Package Installation Errors

**Error**: "EACCES: permission denied" or "gyp ERR!"

**Solution**:
```bash
# Clear npm cache
npm cache clean --force

# Use different registry
npm install --registry https://registry.npmjs.org/

# For permission issues on Linux/Mac
sudo chown -R $(whoami) ~/.npm
```

#### Database Connection Issues

**Error**: "database is locked" or connection timeout

**Solution**:
```python
# For SQLite locking issues
import sqlite3
conn = sqlite3.connect('adzero_trust.db', timeout=20)

# For PostgreSQL connection issues
# Check connection string in .env file
# Verify PostgreSQL service is running
```

#### Frontend Build Errors

**Error**: "Module not found" or TypeScript errors

**Solution**:
```bash
# Clear node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# For TypeScript errors
npm install -D @types/node @types/react @types/react-dom

# Update dependencies
npm update
```

### Performance Issues

#### Slow Assessment Performance

**Symptoms**: Assessments taking longer than expected

**Solutions**:
1. **Increase PowerShell timeout**:
   ```bash
   # In .env file
   POWERSHELL_TIMEOUT=7200  # 2 hours
   ```

2. **Limit assessment scope**:
   ```powershell
   # In PowerShell configuration
   $Global:ADZeroTrustConfig.MaxObjectsToProcess = 50000
   ```

3. **Enable parallel processing**:
   ```powershell
   # Use PowerShell workflows for large environments
   $Global:ADZeroTrustConfig.EnableParallelProcessing = $true
   ```

#### High Memory Usage

**Symptoms**: System running out of memory during assessment

**Solutions**:
1. **Increase system memory** (recommended: 16GB+)
2. **Process in batches**:
   ```powershell
   $Global:ADZeroTrustConfig.BatchSize = 1000
   ```
3. **Enable garbage collection**:
   ```powershell
   [System.GC]::Collect()
   [System.GC]::WaitForPendingFinalizers()
   ```

### Security Issues

#### Certificate Validation Errors

**Error**: SSL certificate validation failures

**Solution**:
```bash
# For development only - disable SSL verification
export PYTHONHTTPSVERIFY=0

# For production - install proper certificates
# Update certificate store
```

#### Authentication Failures

**Error**: "Access denied" or authentication errors

**Solution**:
1. **Verify domain credentials**
2. **Check user permissions**:
   ```powershell
   # Test current user permissions
   whoami /groups
   Get-ADUser $env:USERNAME -Properties MemberOf
   ```
3. **Use service account** for automated assessments

### Getting Help

If you encounter issues not covered in this guide:

1. **Check GitHub Issues**: Search existing issues for similar problems
2. **Create New Issue**: Provide detailed error messages and system information
3. **Community Support**: Join discussions in the GitHub repository
4. **Professional Support**: Contact support@adzero-trust.com for enterprise support

## Upgrade Instructions

### Upgrading from Previous Versions

#### Backup Current Installation

```bash
# Backup database
cp adzero_trust.db adzero_trust.db.backup

# Backup configuration
cp .env .env.backup
cp config.py config.py.backup
```

#### Standard Upgrade Process

```bash
# Pull latest changes
git pull origin main

# Update backend dependencies
cd Backend/adzero_backend
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Update frontend dependencies
cd ../../Frontend/adzero-dashboard
npm update

# Run database migrations (if applicable)
cd ../../Backend/adzero_backend
python src/migrate_db.py
```

#### Version-Specific Upgrade Notes

**Upgrading to v1.1.0**
- New database schema changes require migration
- Updated PowerShell modules with breaking changes
- New configuration options available

**Upgrading to v1.2.0**
- React 18 upgrade requires Node.js 16+
- New authentication system
- Enhanced security features

### Rollback Procedures

If upgrade fails, rollback to previous version:

```bash
# Restore database backup
cp adzero_trust.db.backup adzero_trust.db

# Restore configuration
cp .env.backup .env
cp config.py.backup config.py

# Checkout previous version
git checkout v1.0.0

# Reinstall dependencies
cd Backend/adzero_backend
pip install -r requirements.txt

cd ../../Frontend/adzero-dashboard
npm install
```

---

This installation guide provides comprehensive instructions for setting up ADZero Trust in various environments. For additional support or questions, please refer to the main README.md file or contact the development team.

