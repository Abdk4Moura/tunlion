// define q
const q = (selector, parent = document) => (parent || document).querySelector(selector)
// define modals
// about-us modal
const about_us_modal = q('div#about_us.modal-overlay')
const about_us_open = q('ul > li > .icon-help')
const about_us_close = []
defineModal(about_us_modal, [about_us_open], about_us_close)

// about-app modal
const about_app_modal = q('div#about_app.modal-overlay')
const about_app_open = q('ul > li > .icon-help')
const about_app_close = [
  q('div.actions button#close', about_app_modal)
]
defineModal(about_app_modal, [about_app_open], about_app_close)

function defineModal(modalOverlay, openTriggerElements, closeTriggerElements) {
  if (!modalOverlay) {
    // throw some error
    console.error('modalOverlay not found')
    return
  }
  const modal = modalOverlay.querySelector('div.modal-body')
  function closeModalOverlay() {
    return modalOverlay.style.display = 'none'
  }
  function openModalOverlay() {
    return modalOverlay.style.display = 'block'
  }
  // open event listeners
  for (const openTriggerElement of openTriggerElements) {
    openTriggerElement.addEventListener('click', function () {
      openModalOverlay()
    })
  }

  // close event listeners
  const closeButton = modal.querySelector('.close')
  if (closeButton) closeTriggerElements.push(closeButton)
  if (closeTriggerElements.length === 0) {
    console.warn('closeTriggerElements not found: falling back to default close trigger --> window')
  } else {
    for (const closeTriggerElement of closeTriggerElements) {
      closeTriggerElement.addEventListener('click', function () {
        closeModalOverlay()
      })
    }
  }

  // general close event listener
  modalOverlay.addEventListener('click', (event) => {
    if (!modal.contains(event.target) && event.target != closeButton) {
      closeModalOverlay()
      // this.removeEventListener('click', arguments.callee)
    }
  })
}
