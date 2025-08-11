import logging, os
from logging.handlers import RotatingFileHandler
def configure_logging(log_dir: str):
    os.makedirs(log_dir, exist_ok=True)
    handler = RotatingFileHandler(os.path.join(log_dir,'app.log'), maxBytes=2_000_000, backupCount=3)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
    root = logging.getLogger(); root.setLevel(logging.INFO)
    handler.setFormatter(fmt); root.addHandler(handler)
    console = logging.StreamHandler(); console.setFormatter(fmt); root.addHandler(console)
