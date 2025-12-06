"""
DeadNet Android - Main Entry Point
Minimal server that loads quickly, imports backend lazily
"""

import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('DeadNet')

from flask import Flask, send_from_directory
from flask_cors import CORS

# Get paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(SCRIPT_DIR, 'dist')

# Create minimal Flask app
app = Flask(__name__, static_folder=DIST_DIR, static_url_path='')
CORS(app)

# Serve static files
@app.route('/')
def index():
    return send_from_directory(DIST_DIR, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory(DIST_DIR, path)

# Import API routes lazily
_api_loaded = False

def load_api():
    global _api_loaded
    if _api_loaded:
        return
    
    logger.info("Loading API routes...")
    from deadnet_server import register_routes
    register_routes(app)
    _api_loaded = True
    logger.info("API routes loaded")

# Catch-all for API routes - load on first API call
@app.before_request
def before_request():
    from flask import request
    if request.path.startswith('/api/'):
        load_api()


def start_server(port=5000):
    """Start the Flask server"""
    logger.info(f"Starting DeadNet on port {port}")
    logger.info(f"Static files: {DIST_DIR}")
    app.run(host='127.0.0.1', port=port, debug=False, threaded=True, use_reloader=False)


def stop_server():
    """Stop the server"""
    logger.info("Server stopped")
