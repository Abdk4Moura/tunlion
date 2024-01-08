// state variables
// isIdle: equal('peer.state', 'idle'),
// isPreparingFileTransfer: equal('peer.state', 'is_preparing_file_transfer'),
// hasSelectedFile: equal('peer.state', 'has_selected_file'),
// isSendingFileInfo: equal('peer.state', 'sending_file_info'),
// isAwaitingFileInfo: equal('peer.state', 'awaiting_file_info'),
// isAwaitingResponse: equal('peer.state', 'awaiting_response'),
// hasReceivedFileInfo: equal('peer.state', 'received_file_info'),
// hasDeclinedFileTransfer: equal('peer.state', 'declined_file_transfer'),
// hasError: equal('peer.state', 'error'),

// isReceivingFile: gt('peer.transfer.receivingProgress', 0),
// isSendingFile: gt('peer.transfer.sendingProgress', 0),


const peerState = {
  hasSelectedFile: false,
  hasReceivedFileInfo: false,
  hasDeclinedFileTransfer: false,
  hasError: false,
  isReceivingFileInfo: false,
  isSendingFileInfo: false,
  isAwaitingResponse: false,
  isAwaitingFileInfo: false,
  isReceivingFile: false,
  isSendingFile: false,
  isIdle: true,
  isPreparingFileTransfer: false,
  generalPeerState
}

const generalPeerState = {
  transfer: {
    receivingProgress: 0,
    sendingProgress: 0,
  },
}


// first manually define an element called peerWidget
function peerWidget(userId) {
  const peerDisplayElement = document.createElement('div')
  peerDisplayElement.classList.add('user')
  peerDisplayElement.classList.add('others')
  peerDisplayElement.classList.add(userId)
  peerDisplayElement.innerHTML = `
    <div class="avatar">
      <img src="https://avatars.dicebear.com/api/avataaars/${userId}.svg" alt="avatar">
    </div>
    <div class="name">${userId}</div>
  `
  return peerDisplayElement
}

function onPeerStateChanged(state) {
  // a case that encompases all states
  if (state.hasSelectedFile) {
    hostFileTransferPopover()
  } else if (state.hasReceivedFileInfo) {
    peerFileTransferPopover()
  } else if (state.hasDeclinedFileTransfer) {
  } else if (state.hasError) {
  } else if (state.isReceivingFileInfo) {
  } else if (state.isSendingFileInfo) {
  } else if (state.isAwaitingResponse) {
  } else if (state.isAwaitingFileInfo) {
  } else if (state.isReceivingFile) {
  } else if (state.isSendingFile) {
  } else if (state.isIdle) {
  } else if (state.isPreparingFileTransfer) {
  }
}

const peersDisplayContainer = document.querySelector('div.user.others')

socket.on('new-peer', (userId) => {
  const peerDisplayElement = document.createElement('div')
  peerDisplayElement.classList.add('user')
  peerDisplayElement.classList.add('others')
  peerDisplayElement.classList.add(userId)
  peerDisplayElement.innerHTML = `
    <div class="avatar">
      <img src="https://avatars.dicebear.com/api/avataaars/${userId}.svg" alt="avatar">
    </div>
    <div class="name">${userId}</div>
  `
  peersDisplayContainer.appendChild(peerDisplayElement)
})

// generic popover definition
function definePopover({ content, onConfirm, onCancel, confirmButtonLabel, cancelButtonLabel, filename }, mountPoint) {
  const popover = document.createElement('div')
  popover.classList.add('popover')
  popover.innerHTML = `
    <div class="popover-body">
        <div class="popover-icon">
            <i class="${iconClass(filename)}"></i>
        </div>
        <p>${content}</p>

        <div class="popover-buttons">
            <button type="button" onclick="${onPopoverButtonCancel}">${cancelButtonLabel}</button>
            <button type="button" onclick="${onPopoverButtonConfirm}">${confirmButtonLabel}</button>
        </div>
        <div class="popover-content">
            <p>Are you sure you want to send ${filename}?</p>
            <div class="actions">
                <button class="cancel">${cancelButtonLabel}</button>
                <button class="confirm">${confirmButtonLabel}</button>
            </div>
        </div>
    </div>
  `
  switch (onConfirm) {
    case 'sendFileTransferEnquiry':
      popover.querySelector('button.confirm').onclick = sendFileTransferEnquiry
      break;
    case 'cancelFileTransfer':
      popover.querySelector('button.confirm').onclick = cancelFileTransfer
      break;
    case 'acceptFileTransfer':
      popover.querySelector('button.confirm').onclick = acceptFileTransfer
      break;
  }

  switch (onCancel) {
    case 'abortFileTransfer':
      popover.querySelector('button.cancel').onclick = abortFileTransfer
      break;
    case 'rejectFileTransfer':
      popover.querySelector('button.cancel').onclick = rejectFileTransfer
      break;
    case 'cancelFileTransfer':
      popover.querySelector('button.cancel').onclick = cancelFileTransfer
      break
  }


  const confirmButton = popover.querySelector('button.confirm')
  const cancelButton = popover.querySelector('button.cancel')
  confirmButton.addEventListener('click', onConfirm)
  cancelButton.addEventListener('click', onCancel)

  mountElement(popover, mountPoint)

  // when the user clicks outside the popover, remove it
  document.addEventListener('click', (event) => {
    if (!popover.contains(event.target)) {
      popover.remove()
    }
  })

  return popover
}

function iconClass(filename) {
  if (filename) {
    const regex = /\.([0-9a-z]+)$/i;
    const match = filename.match(regex);
    const extension = match && match[1];

    if (extension) {
      return `glyphicon-${extension.toLowerCase()}`;
    }
  }

  return undefined;
}
