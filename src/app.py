import os
from flask import Flask, send_from_directory
from flask_restx import Api
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from .routes.health import ns as health_ns
from .routes.checks import ns as checks_ns
from .routes.jobs import ns as jobs_ns
from .routes.reporting import ns as report_ns
from .services.logging_conf import configure_logging
from .services.config import load_config
from .services.auth import require_windows_auth_mw

CONF = load_config()
configure_logging(CONF.get('app', {}).get('log_dir', 'logs'))

app = Flask(__name__, static_folder='../webui', static_url_path='/ui')
api = Api(app, version='1.2', title='AD Zero Trust Assessment API', doc='/api/docs')
api.add_namespace(health_ns, path='/')
api.add_namespace(checks_ns, path='/')
api.add_namespace(jobs_ns, path='/')
api.add_namespace(report_ns, path='/')

@app.before_request
def _win_auth():
    return require_windows_auth_mw()

@app.route('/metrics')
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/ui')
def ui_root():
    return send_from_directory('../webui', 'index.html')

if __name__ == '__main__':
    app.run(host=CONF.get('app', {}).get('host', '127.0.0.1'),
            port=int(CONF.get('app', {}).get('port', 5050)))
