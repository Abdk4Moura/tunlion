import { NotifiedElement, Placeholder, Types, StateNotifier } from "./framework.js";

const user = {
  name: randomName(),
  avatar: `https://avatars.dicebear.com/api/avataaars/${randomName()}.svg`,
  uuid: null,
}


const userStateNotifier = new StateNotifier(user);

const mountPoint = document.querySelector(".avatar")
const userWidget = new NotifiedElement({
  mountPoint,
  mountOptions: {
    templateAlreadyExistent: true,
    replaceElemInMountPoint: false,
  },
  stateNotifier: userStateNotifier,
  templateFunction: (_) => {
    const user = this.stateNotifier.state
    return {
      // 'root': 'div.avatar',
      'img': Placeholder(Types.ATTR,
        {
          src: user.avatar,
          alt: user.name,
          title: `peer id: ${user.uuid}`
        }),
      '.user-info .user-label #userlabel': user.name,
    }
  }
});

userWidget.render();

// helpers
function randomName() {
  const adjectives = [
    "autumn", "hidden", "bitter", "misty", "silent", "empty", "dry", "dark",
    "summer", "icy", "delicate", "quiet", "white", "cool", "spring", "winter",
    "patient", "twilight", "dawn", "crimson", "wispy", "weathered", "blue",
  ]
  const nouns = [
    "waterfall", "river", "breeze", "moon", "rain", "wind", "sea", "morning",
    "snow", "lake", "sunset", "pine", "shadow", "leaf", "dawn", "glitter",
    "forest", "hill", "cloud", "meadow", "sun", "glade", "bird", "brook",
    "butterfly", "bush", "dew", "dust", "field", "fire", "flower", "firefly",
    "feather", "grass", "haze", "mountain", "night", "pond", "darkness",
    "snowflake", "silence", "sound", "sky", "shape", "surf", "thunder",
    "violet", "water", "wildflower", "wave", "water", "resonance", "sun",
    "wood", "dream", "cherry", "tree", "fog", "frost", "voice", "paper",
    "frog", "smoke", "star",
  ]
  return (
    adjectives[Math.floor(Math.random() * adjectives.length)] +
    "_" +
    nouns[Math.floor(Math.random() * nouns.length)]
  )
}
