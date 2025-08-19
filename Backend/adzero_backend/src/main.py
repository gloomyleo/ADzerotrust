import os
import sys
# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS
from src.models.assessment import db
from src.routes.assessment import assessment_bp
from src.routes.powershell import powershell_bp
from src.routes.dashboard import dashboard_bp
from src.routes.roadmap import roadmap_bp

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
app.config['SECRET_KEY'] = 'adzero_trust_secret_key_2025'

# Enable CORS for all routes
CORS(app, origins="*")

# Register blueprints
app.register_blueprint(assessment_bp, url_prefix='/api')
app.register_blueprint(powershell_bp, url_prefix='/api')
app.register_blueprint(dashboard_bp, url_prefix='/api')
app.register_blueprint(roadmap_bp, url_prefix='/api')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'database', 'adzero_trust.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    """Serve frontend files and handle SPA routing"""
    static_folder_path = app.static_folder
    if static_folder_path is None:
        return "Static folder not configured", 404

    if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        index_path = os.path.join(static_folder_path, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(static_folder_path, 'index.html')
        else:
            return "ADZero Trust Dashboard - Frontend not deployed", 404

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "ADZero Trust Backend",
        "version": "1.0",
        "author": "Moazzam Jafri"
    }

@app.route('/api/info')
def api_info():
    """API information endpoint"""
    return {
        "name": "ADZero Trust API",
        "version": "1.0",
        "description": "Active Directory Zero Trust Assessment Tool API",
        "author": "Moazzam Jafri",
        "endpoints": {
            "assessments": "/api/assessments",
            "powershell": "/api/powershell",
            "dashboard": "/api/dashboard",
            "roadmap": "/api/roadmap"
        }
    }

if __name__ == '__main__':
    print("=" * 60)
    print("ADZero Trust Backend Server")
    print("Author: Moazzam Jafri")
    print("Active Directory Zero Trust Assessment Tool")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)

