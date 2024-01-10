// peer is defined here
import Signalling from './signalling.js';

const configuration = {
  iceServers: [
    {
      urls: [
        'stun:stun1.l.google.com:19302',
        'stun:stun2.l.google.com:19302',
      ],
    },
  ],
  iceCandidatePoolSize: 10,
};

export default class Peer {
  constructor(id, firebase_or_socketio) {
    this.id = id;
    this.name = randomName();
    this.pc = createPC();
    this.signalling = new Signalling(pc, firebase_or_socketio);
    this.dataChannel = new DataChannel(pc);
    this._isConnected = false;
  }

  fireEvent(event) {}

  connect() {
    // create Room
    this.signalling.createRoom();
    this.dispatchEvent('connect')
  }

  join(roomId) {
    this.signalling.joinRoom(roomId);
    this.dispatchEvent('join')
  }

  sendData() {
    if (!this._isConnected) {
      throw new Error('Not connected');
    }
    this.channel.sendData();
  }

  createPC() {
    let pc = new RTCPeerConnection(configuration);
    this.registerPeerConnectionListeners();

    return pc;
  }

  registerPeerConnectionListeners() {
    this.pc.addEventListener('icegatheringstatechange', () => {
      console.log(
        `ICE gathering state changed: ${this.pc.iceGatheringState}`);
    });

    this.pc.addEventListener('connectionstatechange', () => {
      console.log(`Connection state change: ${this.pc.connectionState}`);
    });

    this.pc.addEventListener('signalingstatechange', () => {
      console.log(`Signaling state change: ${this.pc.signalingState}`);
    });

    this.pc.addEventListener('iceconnectionstatechange ', () => {
      console.log(
        `ICE connection state change: ${this.pc.iceConnectionState}`);
    });
  }
}

class DataChannel {
  constructor(pc) {
    this.pc = pc;
    this.dataChannel = pc.createDataChannel('dataChannel');
    init()
  }

  init() {
    this.dataChannel.binaryType = 'arraybuffer';
    this.dataChannel.addEventListener('open', onOpen);
    this.dataChannel.addEventListener('close', onClose);
    this.dataChannel.addEventListener('error', onError);
  }

  sendData() {
    // TODO: make file be in a state that can be sent
    const file = fileInput.files[0];
    console.log(`File is ${[file.name, file.size, file.type, file.lastModified].join(' ')}`);

    // Handle 0 size files.
    statusMessage.textContent = '';
    downloadAnchor.textContent = '';

    if (file.size === 0) {
      bitrateDiv.innerHTML = '';
      statusMessage.textContent = 'File is empty, please select a non-empty file';
      closeDataChannels();
      return;
    }

    sendProgress.max = file.size;
    receiveProgress.max = file.size;
    const chunkSize = 16384;
    fileReader = new FileReader();
    let offset = 0;
    fileReader.addEventListener('error', error => console.error('Error reading file:', error));
    fileReader.addEventListener('abort', event => console.log('File reading aborted:', event));
    fileReader.addEventListener('load', e => {
      console.log('FileRead.onload ', e);
      dataChannel.send(e.target.result);
      offset += e.target.result.byteLength;
      sendProgress.value = offset;
      if (offset < file.size) {
        readSlice(offset);
      }
    });
    const readSlice = o => {
      console.log('readSlice ', o);
      const slice = file.slice(offset, o + chunkSize);
      fileReader.readAsArrayBuffer(slice);
    };
    readSlice(0);
  }

  onOpen() {
    const readyState = this.dataChannel.readyState;
    console.log('Send channel state is: ' + readyState);
    if (readyState === 'open') {
      sendData();
    }
  }

  onError(error) {
    if (dataChannel) {
      console.error('Error in dataChannel:', error);
      return;
    }
    console.log('Error in dataChannel which is already closed:', error);
  }

  onClose() {
    const readyState = this.dataChannel.readyState;
    console.log('Send channel state is: ' + readyState);
  }

  close() {
    this.dataChannel.close();
  }
}

function randomName() {
  return 'user' + Math.floor(Math.random() * 10000);
}
