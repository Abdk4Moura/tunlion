#!/usr/bin/env python3

import os
from uuid import uuid4
from flask import (
    Flask,
    request,
    session,
    send_file,
    render_template,
)


# from raven import Client  # For Sentry integration
from flask_socketio import SocketIO, emit, join_room, leave_room
import platform

app = Flask(__name__)
socketio = SocketIO(app)

app.static_folder = "assets"


users_in_room = {}
rooms_sid = {}
names_sid = {}


def generate_unique_room_id():
    return str(uuid4())


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
    context = {room: room_id}
    if room_id not in rooms_sid:
        return "Room not found", 404

    return render_template(
        "index.html",
    )


# SocketIO setup
@socketio.on("connect")
def on_connect():
    sid = request.sid
    print("New socket connected ", sid)


@socketio.on("join-room")
def on_join_room(data):
    sid = request.sid
    room_id = data.get("room_id") or generate_unique_room_id()
    display_name = data.get("name")

    join_room(room_id)
    rooms_sid[sid] = room_id
    names_sid[sid] = display_name

    print(f"[{room_id}] New member joined: {display_name}<{sid}>")
    emit(
        "user-connect",
        {"sid": sid, "name": display_name},
        broadcast=True,
        include_self=True,
        room=room_id,
    )

    handle_user_list(sid, room_id)  # Refactored for clarity

    # Broadcast room creation or joining
    emit("room-update[create/join]", room_id, room=room_id)


@socketio.on("leave-room")
def on_leave_room(data):
    sid = request.sid
    room_id = rooms_sid.get(sid)
    display_name = data.get("name")

    leave_room(room_id)
    if room_id is not None:
        rooms_sid[sid].remove(sid)
    del names_sid[sid]

    print(f"[{room_id}] New member joined: {display_name}<{sid}>")
    emit(
        "user-leave-room",
        {"sid": sid, "name": display_name},
        broadcast=True,
        include_self=False,
        room=room_id,
    )

    emit("room-update[leave]", room_id, room=room_id)


def handle_user_list(sid, room_id):
    if room_id not in users_in_room:
        users_in_room[room_id] = [sid]
        emit("user-list", {"my_id": sid}, room=room_id)  # Send own ID only
    else:
        usrlist = {u_id: names_sid[u_id] for u_id in users_in_room[room_id]}
        emit("user-list", {"list": usrlist, "my_id": sid}, room=room_id)
        users_in_room[room_id].append(sid)


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


@socketio.on("ice-candidate")
def on_data(candidate):
    room_id = rooms_sid[request.sid]

    emit("ice-candidate", candidate, room=room_id, include_self=False)


@socketio.on("offer")
def on_offer(offer):
    room_id = rooms_sid[request.sid]

    emit("offer", offer, room=room_id, include_self=False)


@socketio.on("answer")
def on_answer(answer):
    room_id = rooms_sid[request.sid]

    emit("answer", answer, room=room_id, include_self=False)


if any(platform.win32_ver()):
    socketio.run(app, debug=True)
