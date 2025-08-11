import os, json
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from datetime import datetime
def export_pdf(out_dir='out', title='AD Zero Trust Assessment – Executive Summary'):
    os.makedirs(out_dir, exist_ok=True)
    pdf=os.path.join(out_dir,'executive_summary.pdf')
    c=canvas.Canvas(pdf, pagesize=letter); W,H=letter
    c.setFont('Helvetica-Bold', 18); c.drawString(1*inch, H-1.1*inch, title)
    c.setFont('Helvetica', 9); c.drawString(1*inch, H-1.3*inch, f'Generated: {datetime.utcnow().isoformat()}Z')
    scores={}; results=[]
    try:
        with open(os.path.join(out_dir,'scores.json')) as f: scores=json.load(f)
        with open(os.path.join(out_dir,'results.json')) as f: results=json.load(f)
    except: pass
    y=H-1.6*inch; c.setFont('Helvetica-Bold', 12); c.drawString(1*inch,y,"Scores"); y-=16; c.setFont('Helvetica', 10)
    for k in ['Identity','Devices','Network','Apps','Data','overall']:
        if k in scores: c.drawString(1*inch, y, f"- {k}: {scores[k]}"); y-=14
    y-=6; c.setFont('Helvetica-Bold', 12); c.drawString(1*inch,y,"Highlights"); y-=16; c.setFont('Helvetica', 9)
    for r in results[:14]:
        status='OK' if 'error' not in r else f"ERROR: {r['error'][:70]}"
        c.drawString(1*inch, y, f"- {r.get('id')}: {r.get('description','')[:80]} [{status}]"); y-=12
        if y < 1.2*inch: c.showPage(); y=H-1.0*inch
    c.save(); return pdf
