const preloader = document.querySelector('.preloader');

// by default, the preloader is visible
// when the page loads, we want to fade out the preloader
window.addEventListener('load', function () {
  setTimeout(preloaderFadeOut, 1000);
})

function preloaderFadeOut() {
  preloader.style.opacity = '0';
  preloader.style.display = 'none';
}
