<div align="center">

# 🔐 AD Zero Trust Assessor
**Production-ready Active Directory assessment** with hardened PowerShell collectors, Zero Trust scoring, async jobs, evidence pack, and a tiny web UI.  
*Signature verification · JEA support · Executive PDF · Swagger · Prometheus · MkDocs*

[![CI](https://img.shields.io/github/actions/workflow/status/gloomyleo/zerotrust/ci.yml?label=CI)](./.github/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs--material-blue)](https://gloomyleo.github.io/zerotrust/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

</div>

## ✨ Highlights
- ✅ **Safe PS runner**: timeouts, arg sanitization, transcripts, **Authenticode** enforcement
- 🔐 **JEA option**: run via least-privileged endpoint
- 🛡️ **Zero Trust scoring** across pillars (Identity/Devices/Network/Apps/Data)
- 📦 **Evidence pack**: JSON, CSV, and executive **PDF**
- 🧩 **Data-driven checks** via `checks/manifest.yaml`
- 📊 **Metrics** at `/metrics` · **Swagger** at `/api/docs`
- 🖥️ **Web UI**: trigger runs and download reports

## 🚀 Quick Start (Windows recommended)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m src.app
# open http://127.0.0.1:5050/ui
```
Then use the UI or Swagger to **POST /run_checks**, watch job status at **GET /jobs/{id}**, then download **/report/latest**.

## 🔧 Configuration
Edit `config.yaml`:
```yaml
ps:
  shell: pwsh
  execution_policy: AllSigned   # RemoteSigned for labs; AllSigned for prod
  timeout_sec: 180
  transcript_dir: logs/transcripts
  configuration_name: ''        # e.g., 'JEA-AD-ReadOnly' to enable JEA
app:
  host: 127.0.0.1
  port: 5050
  out_dir: out
  log_dir: logs
```

## 📚 Docs
Full docs live at **/docs** (MkDocs). See **/docs/usage.md** for endpoints and **/docs/checks.md** for the list of collectors.

## 📝 License
MIT © 2025

---

### 🙌 About the author

**Moazzam Jafri** — a cyber security leader with more than two decades of experience managing security programs for multinational organizations.  
I built this to **give back to the community** and help teams accelerate their Zero Trust journey.

