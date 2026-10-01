"""
Gunicorn configuration file for Render deployment and production serving.
"""

import os

# Render sets the PORT environment variable dynamically
port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{port}"

# Single worker with multiple threads ensures in-memory simulator
# state is cleanly shared across concurrent HTTP requests.
workers = int(os.environ.get("WEB_CONCURRENCY", "1"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "120"))

# Disable control socket to avoid permission issues across varied container environments
control_socket_disable = True

# Log directly to stdout and stderr for Render console
accesslog = "-"
errorlog = "-"
loglevel = "info"
