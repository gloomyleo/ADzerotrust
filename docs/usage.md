# Usage

## Start
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m src.app
```
Open `http://127.0.0.1:5050/ui` or `http://127.0.0.1:5050/api/docs`

## Endpoints
- `POST /run_checks` → returns `job_id`
- `GET /jobs/{job_id}` → `queued|running|completed|error`
- `GET /report/latest` → PDF

