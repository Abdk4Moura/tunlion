// const peerStateNotifier = StateNotifier(peerState);
// // Path: circularProgress.js
// // using GenericElement
// //
// // Usage: new CircularProgress({ mountPoint, mountOptions, initProps })
// class CircularProgress extends NotifiedElement {
//   templateFunction({ initProps }) {
//     const { initProps } = initProps;
//     const state = stateNotifier.state;
//     const { value, color } = state;
//     const rgb = COLORS[color];

//     var style = htmlSafe(`fill: rgba(${rgb}, .5)`);
//     let innerHTML = `
// <svg width="76" height="76" viewport="0 0 76 76" style="${style}">
//     <path class="break" transform="translate(38, 38)" d="${path()}" />
// </svg>
// `
//     return innerHTML
//   }
// }

// // Path: app/templates/components/circularProgress.html
// const avatar = document.querySelector(".avatar");
// const state = { value: 0, color: "blue" };
// let values = {
//   mountPoint: avatar,
//   initProps: {
//     stateProps:
//       { value: 0, color: "blue" },
//     props: {}
//   },
//   peerStateNotifier
// }

// const aa = new CircularProgress(values);

const COLORS = {
  blue: '0, 136, 204',
  orange: '197, 197, 51',
};


function path() {
  const π = Math.PI;
  const α = this.args.value * 360;
  const r = (α * π) / 180;
  const mid = α > 180 ? 1 : 0;
  const x = Math.sin(r) * 38;
  const y = Math.cos(r) * -38;

  return `M 0 0 v -38 A 38 38 1 ${mid} 1 ${x} ${y} z`;
}

function defineCircularProgress(options, mountPoint) {
  // TODO: add required options including in the genericComponent.js
  const { _path: path, color, value } = options
  if (_path === undefined) {
    _path = path();
  }
  const rgb = COLORS[color];
  var style = htmlSafe(`fill: rgba(${rgb}, .5)`);
  circularProgressInnerHTML = `
<svg width="76" height="76" viewport="0 0 76 76" style="${style}">
    <path class="break" transform="translate(38, 38)" d="${path}" />
</svg>
`
  const element = document.createElement('div')
  element.innerHTML = circularProgressInnerHTML
  mountCircularProgress(element, mountPoint)

  return element
}

// Path: circularProgress.js
// Usage: circularProgress({ style: 'stroke: #000; stroke-width: 2px; fill: none;' })

// Mounting-replacing the element
function mountCircularProgress(element, mountPoint) {
  mountPoint.parentNode.replaceChild(element, mountPoint)
}


