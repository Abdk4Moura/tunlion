#!/usr/bin/env python3
#
import os
import uuid
import hashlib
from http import HTTPStatus
from flask import Flask, request, jsonify, send_file
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.middleware.dispatcher import DispatcherMiddleware

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)  # Enable trust proxy
app.static_folder = "static"

# Environment variables
FIREBASE_SECRET = os.environ.get("FIREBASE_SECRET")
SECRET = os.environ.get("SECRET")
PORT = int(os.environ.get("PORT", 5000))  # Default to 5000 if not set

# Static files configuration
base_dir = "dist"
static_files = {"assets": "max-age=31104000000", ".well-known": None}  # ~1 year

# Middleware setup
# app.wsgi_app = DispatcherMiddleware(
#     app.wsgi_app,
#     {"/static": app.send_static_file
#      },  # Correctly reference the static file handler
# )  # Allow for multiple WSGI apps and mount static files


# Middleware functions
@app.before_request
def log_request():
    app.logger.info(f"{request.method} {request.path}")


@app.after_request
def add_header(response):
    response.headers["X-Content-Type-Options"] = "nosniff"  # Security header
    return response


# API endpoints
@app.route("/")
def index():
    root = os.path.join(os.path.dirname(__file__), base_dir)
    return send_file(os.path.join(root, "index.html"))


@app.route("/rooms/<room_id>")
def rooms(room_id):
    root = os.path.join(os.path.dirname(__file__), base_dir)
    return send_file(os.path.join(root, "index.html"))


@app.route("/room")
def get_room_name():
    ip = request.headers.get("cf-connecting-ip", request.remote_addr)
    hashed_ip = hashlib.md5(f"{SECRET}{ip}".encode("utf-8")).hexdigest()
    return jsonify({"name": hashed_ip}), HTTPStatus.OK


@app.route("/auth")
def create_auth_token():
    ip = request.headers.get("cf-connecting-ip", request.remote_addr)
    uid = str(uuid.uuid4())
    # TODO: Implement Firebase token generation using FIREBASE_SECRET
    token = "placeholder_token"  # Replace with actual token generation
    return jsonify({"id": uid, "token": token, "public_ip": ip}), HTTPStatus.OK


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
