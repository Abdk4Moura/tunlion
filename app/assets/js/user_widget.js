import { NotifiedElement, Placeholder, Types } from "./framework.js";

const userStateNotifier = new StateNotifier(user);
const userWidget = new NotifiedElement({
  mountPoint: document.querySelector(".avatar"),
  userStateNotifier,
  templateFunction: (_) => {
    const user = this.userStateNotifier.state
    return {
      'root': 'div.avatar',
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
