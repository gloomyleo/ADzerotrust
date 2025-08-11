from flask import request, abort
from .config import load_config

CONF = load_config()
REQ_WIN_AUTH = CONF.get('app', {}).get('require_windows_auth', False)
TRUSTED_HEADER = CONF.get('app', {}).get('trusted_auth_header', 'X-Remote-User')

def current_user():
    # Prefer IIS/Reverse Proxy integrated auth header
    user = request.headers.get(TRUSTED_HEADER)
    # Fallback to REMOTE_USER set by upstream server (IIS/HTTP.SYS)
    if not user:
        user = request.environ.get('REMOTE_USER')
    return user

def require_windows_auth_mw():
    if not REQ_WIN_AUTH:
        return
    user = current_user()
    if not user:
        abort(401, description="Windows Integrated Authentication required")
