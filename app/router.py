#!/usr/bin/env python3

from flask import Flask

app = Flask(__name__)

# Configuration (similar to Ember's `config`)
#  app.config.from_object("config.DevelopmentConfig")  # Load from a config file

# Define routes
# @app.route("/")
# def index():
#     return "Welcome to the ShareDrop app!"


# @app.route("/rooms/<room_id>")  # URL parameter using angle brackets
# def room(room_id):
#     return f"You are in room {room_id}"


if __name__ == "__main__":
    app.run()
