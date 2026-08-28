"""Gunicorn config for Yiriba License Server on Render."""
import os

bind = "0.0.0.0:" + os.environ.get("PORT", "5000")
workers = 2
threads = 4
timeout = 120
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
preload_app = True
