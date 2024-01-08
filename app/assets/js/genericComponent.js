class GenericElement {
  constructor({ mountPoint, mountOptions, initProps, templateFunction }) {
    const { replaceElemInMountPoint } = mountOptions;

    let mainElem;
    if (!replaceElemInMountPoint) {
      mainElem = mountPoint;
    } else {
      mainElem = document.createElement('div').append;
      mountPoint.parentNode.replaceChild(mainElem, mountPoint);
    }
    const childrenSlot = mainElem.querySelector('div.genericElemSlot')
    this.childrenSlot = childrenSlot;

    this.mountPoint = mainElem;
    this._state = initProps.stateProps;
    this.attrs = initProps.props;
    this.templateFunction = templateFunction;

    this.render();
  }

  appendChild(child) {
    if (isSingletonElement) {
      throw new Error('Cannot append child to singleton element');
    }
    this.childrenSlot.appendChild(child);
  }

  appendChildren(children) {
    if (isSingletonElement) {
      throw new Error('Cannot append child to singleton element');
    }
    children.forEach((child) => this.childrenSlot.appendChild(child));
  }

  get children() {
    return this.childrenSlot.children;
  }

  set children(children) {
    if (isSingletonElement) {
      throw new Error('Cannot append child to singleton element');
    }
    this.childrenSlot.innerHTML = '';
    children.forEach((child) => this.childrenSlot.appendChild(child));
  }

  get hasChildren() {
    return !this.isSingletonElement || this.childrenSlot.children.length > 0;
  }

  get isSingletonElement() {
    return !this.childrenSlot;
  }

  get state() {
    return this._state;
  }

  set state(newState) {
    throwIfInvalidState(newState);
    this._state = newState;
  }

  throwIfInvalidState(state) {
    if (typeof state !== 'object') {
      throw new Error('State must be an object');
    }

    for (const prop in state) {
      // check if newState does not contain a prop not
      // previously defined
      if (!prevState.hasOwnProperty(prop)) {
        throw new Error(`State property ${prop} does not exist`);
      }
    }
  }

  setState(newState) {
    const prevState = { ...state };

    throwIfInvalidState(newState);
    state = { ...state, ...newState };

    // Check if any state property has changed
    if (!areStatesEqual(prevState, state)) {
      render();
    }
  }

  areStatesEqual(state1, state2) {
    // Compare all properties in the state
    for (const prop in state1) {
      if (state1[prop] !== state2[prop]) {
        return false;
      }
    }
    return true;
  }

  render() {
    const templateResult = this.templateFunction({ ...this.state, ...this.attrs });
    this.mountPoint.innerHTML = templateResult;
  }
}

// Usage remains the same as provided in the previous response

// Example: Change state and trigger re-render
// genericElement.setState({ hasSelectedFile: true });

// Usage:
// let initProps = {
//     stateProps: {
//       hasSelectedFile: false,
//       hasReceivedFileInfo: false,
//     },
//     props: {
//       userId: 'user1',
//    },
// }
//
// let template = function (initProps) {
//    let {stateProps, props} = initProps
//    // all the properties here:
//    { ...stateProps...  } = stateProps
//    { ...props...  } = props
//
//    // I want to be able to enter values like:
//    return `div class="user ${props.userId}"></div>`
// }
//
//
// let mountOptions = {
//   replaceElemInMountPoint: true,
// }

// GenericElement({ mountElem, mountOptions, initProps, template})
