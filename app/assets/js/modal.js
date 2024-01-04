const openModalButton = document.getElementById('openModalBtn')
const modal = document.querySelector('div.modal-overlay')
openModalButton.addEventListener('click', function () {
  documnet.getElementById('')
});

const closeButton = document.querySelector('div.modal > div.modal-content > .close')
closeButton.addEventListener('click', function () {
  document.getElementById('myModal').style.display = 'none';
});

window.addEventListener('click', function (event) {
  if (event.target == document.getElementById('myModal')) {
    document.getElementById('myModal').style.display = 'none';
  }
});
