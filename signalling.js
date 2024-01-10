class Signalling {
  constructor(firebase_or_socketio) {
    this._db = null;
    this._io = null;
    if (firebase_or_socketio === 'firebase') {
      this._db = firebase.firestore();
    } else {
      this._io = io();
    }
    this.channel = this._db || this._io
  }

  get db() {
    if (!this._db) {
      throw new Error('Signalling channel is not firebase');
    }
    return this._db;
  }

  get isFirebase() {
    return !!this._db;
  }

  get isSocketIO() {
    return !!this._io;
  }

  get io() {
    if (!this._io) {
      throw new Error('Signalling channel is not socket.io');
    }
    return this._io;
  }

  addOffer(roomWithOffer) {
    if (isFirebase) {
      const roomRef = this.db.collection('rooms').add(roomWithOffer);

      monitorFirebaseRoomRef(roomRef);
      return
    }
    this.io.emit('offer', roomWithOffer);
  }

  monitorFirebaseRoomRef(roomRef) {
    roomRef.onSnapshot(async snapshot => {
      const data = snapshot.data();
      if (!pc.currentRemoteDescription && data && data.answer) {
        console.log('Got remote description: ', data.answer);
        const rtcSessionDescription = new RTCSessionDescription(data.answer);
        await pc.setRemoteDescription(rtcSessionDescription);
      }
    });
  }
}
