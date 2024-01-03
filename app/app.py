#!/usr/bin/env python3

import os
from flask import (
    Flask,
    request,
    session,
    send_file,
    render_template,
    send_from_directory,
)
import jinja2

# from raven import Client  # For Sentry integration
from flask_socketio import SocketIO, emit, join_room
import platform

app = Flask(__name__)
socketio = SocketIO(app)

app.static_folder = "assets"

users_in_room = {}
rooms_sid = {}
names_sid = {}

# Flask Routes and Middlewares

# Error handling middleware
@app.errorhandler(500)
def handle_500(error):
    # client.captureException()
    return "Internal Server Error", 500


# @app.route("/static/<path:path>")
# def serve_static(path):
#     return send_from_directory("assets", path)


# Routing and other application logic
@app.route("/")
def index():
    context = {}
    return render_template("index.html", **context)


@app.route("/join", methods=["GET"])
def join():
    display_name = request.args.get("display_name")
    mute_audio = request.args.get("mute_audio")  # 1 or 0
    mute_video = request.args.get("mute_video")  # 1 or 0
    room_id = request.args.get("room_id")
    session[room_id] = {
        "name": display_name,
        "mute_audio": mute_audio,
        "mute_video": mute_video,
    }
    return render_template(
        "join.html",
        room_id=room_id,
        display_name=session[room_id]["name"],
        mute_audio=session[room_id]["mute_audio"],
        mute_video=session[room_id]["mute_video"],
    )


@app.route("/rooms/<room_id>")  # URL parameter using angle brackets
def room(room_id):
    return f"You are in room {room_id}"


# SocketIO setup


@socketio.on("connect")
def on_connect():
    sid = request.sid
    print("New socket connected ", sid)


@socketio.on("join-room")
def on_join_room(data):
    sid = request.sid
    room_id = data["room_id"]
    display_name = session[room_id]["name"]

    # register sid to the room
    join_room(room_id)
    rooms_sid[sid] = room_id
    names_sid[sid] = display_name

    # broadcast to others in the room
    print("[{}] New member joined: {}<{}>".format(room_id, display_name, sid))
    emit(
        "user-connect",
        {"sid": sid, "name": display_name},
        broadcast=True,
        include_self=False,
        room=room_id,
    )

    # add to user list maintained on server
    if room_id not in users_in_room:
        users_in_room[room_id] = [sid]
        emit("user-list", {"my_id": sid})  # send own id only
    else:
        usrlist = {u_id: names_sid[u_id] for u_id in users_in_room[room_id]}
        # send list of existing users to the new member
        emit("user-list", {"list": usrlist, "my_id": sid})
        # add new member to user list maintained on server
        users_in_room[room_id].append(sid)

    print("\nusers: ", users_in_room, "\n")


@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    room_id = rooms_sid[sid]
    display_name = names_sid[sid]

    print("[{}] Member left: {}<{}>".format(room_id, display_name, sid))
    emit(
        "user-disconnect",
        {"sid": sid},
        broadcast=True,
        include_self=False,
        room=room_id,
    )

    users_in_room[room_id].remove(sid)
    if len(users_in_room[room_id]) == 0:
        users_in_room.pop(room_id)

    rooms_sid.pop(sid)
    names_sid.pop(sid)

    print("\nusers: ", users_in_room, "\n")


@socketio.on("data")
def on_data(data):
    sender_sid = data["sender_id"]
    target_sid = data["target_id"]
    if sender_sid != request.sid:
        print("[Not supposed to happen!] request.sid and sender_id don't match!!!")

    if data["type"] != "new-ice-candidate":
        print("{} message from {} to {}".format(data["type"], sender_sid, target_sid))
    socketio.emit("data", data, room=target_sid)


if any(platform.win32_ver()):
    socketio.run(app, debug=True)
