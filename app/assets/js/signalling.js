export default class Signalling {
  constructor(pc, firebase_or_socketio) {
    this._db = null;
    this._io = null;
    this._roomRef = null;
    this._roomId = null;
    this.availableRooms = [];
    this.pc = pc;
    if (firebase_or_socketio.firebase === 'firebase') {
      this._db = firebase.firestore();
    } else {
      this._io = firebase_or_socketio.io;
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

  createRoom() {
    const roomWithOffer = {
      offer: {
        type: 'offer',
        sdp: offer.sdp,
      },
    };
    addOffer(roomWithOffer);
  }

  monitorRooms() {
    if (isFirebase) {
      this.listenForChangesInCreatedRoomFirebase()
      return
    }
    this.monitorSocketIO()
  }

  joinRoom(roomId) {
    if (isFirebase) {
      this._roomRef = this.db.collection('rooms').doc(this._roomId);
      monitorFirebaseRoomRef();
      return
    }
  }

  addOffer(roomWithOffer) {
    if (isFirebase) {
      this._roomRef = this.db.collection('rooms').add(roomWithOffer);
      this._roomId = this.roomRef.id;

      monitorFirebaseRoomRef();
      return
    }

    this.io.emit('offer', roomWithOffer);
    // assign roomId
    this.io.on('answer', answer => {
      console.log('Got answer: ', answer);
    })
  }

  listen() {
    if (isFirebase) {
      this.listenForChangesInCreatedRoomFirebase()
      return
    }
    this.listenForChangesInCreatedRoomSocketIO()
  }

  listenForAvailableRooms() {
    if (isFirebase) {
      this.db.collection('rooms').onSnapshot(snapshot => {
        snapshot.docChanges().forEach(change => {
          if (change.type === 'added') {
            const room = change.doc.data();
            console.log(`Got available room: ${JSON.stringify(room)}`);
            this.availableRooms.push(room);
          } else if (change.type === 'removed') {
            const room = change.doc.data();
            console.log(`Room was removed: ${JSON.stringify(room)}`);
            this.availableRooms.filter(r => r.id !== room.id);
          }
        });
      });
      return
    }

    // socketio
    this.io.on('new.room', rooms => {
      console.log('Got available rooms: ', rooms);
      this.availableRooms = rooms;
    });

    this.io.on('removed.room', room => {
      console.log('Room was removed: ', room);
      this.availableRooms.filter(r => r.id !== room.id);
    });
  }

  listenForChangesInCreatedRoomFirebase() {
    roomRef.onSnapshot(async snapshot => {
      const data = snapshot.data();
      if (!this.pc.currentRemoteDescription && data && data.answer) {
        console.log('Got remote description: ', data.answer);
        const rtcSessionDescription = new RTCSessionDescription(data.answer);
        await pc.setRemoteDescription(rtcSessionDescription);
      }
    });

    roomRef.collection('calleeCandidates').onSnapshot(snapshot => {
      snapshot.docChanges().forEach(async change => {
        if (change.type === 'added') {
          let data = change.doc.data();
          console.log(`Got new remote ICE candidate: ${JSON.stringify(data)}`);
          await pc.addIceCandidate(new RTCIceCandidate(data));
        }
      });
    })
  }

  listenForChangesInCreatedRoomSocketIO() {
    this.io.on('offer', async offer => {
      console.log('Got offer: ', offer);
      await pc.setRemoteDescription(new RTCSessionDescription(offer));
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      this.io.emit('answer', answer);
    });

    this.io.on('answer', answer => {
      console.log('Got answer: ', answer);
      pc.setRemoteDescription(new RTCSessionDescription(answer));
    });

    this.io.on('ice-candidate', async candidate => {
      console.log('Got candidate: ', candidate);
      await pc.addIceCandidate(new RTCIceCandidate(candidate));
    })
  }
}
