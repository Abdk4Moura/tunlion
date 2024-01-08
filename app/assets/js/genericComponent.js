// StateNotifier class
// Usage: let stateNotifier = new StateNotifier({ hasSelectedFile: false, hasReceivedFileInfo: false });
class StateNotifier {
  constructor(initialState) {
    this.state = initialState;
    this.listeners = [];
  }

  getState() {
    return this.state;
  }

  setState(newState) {
    this.state = { ...this.state, ...newState };
    this.notifyListeners();
  }

  addListener(listener) {
    this.listeners.push(listener);
  }

  removeListener(listener) {
    this.listeners = this.listeners.filter((l) => l !== listener);
  }

  notifyListeners() {
    this.listeners.forEach((listener) => {
      if (typeof listener === 'function') {
        listener();
      }
    });
  }
}

class GenericElement {
  constructor({ mountPoint, mountOptions, initProps, templateFunction }) {
    const { replaceElemInMountPoint } = mountOptions;

    let mainElem;
    if (!replaceElemInMountPoint) {
      mainElem = mountPoint;
    } else {
      mainElem = document.createElement('div');
      mountPoint.parentNode.replaceChild(mainElem, mountPoint);
    }
    this._replaceElemInMountPoint = true;
    const childrenSlot = mainElem.querySelector('div.genericElemSlot')
    this.childrenSlot = childrenSlot;

    this.actualMointPoint = mainElem;
    this._state = initProps.stateProps;
    this.props = initProps.props;
    this.templateFunction = templateFunction;


    beforeMount();
    update();
  }

  appendChild(child) {
    if (isSingletonElement) {
      throw new Error('Cannot append child to singleton element');
    }
    this.childrenSlot.appendChild(child);
  }

  // docstring
  // children: array of elements
  //
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
      update();
    }
    return state
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

  update() {
    render();
    this.componentDidRender();
  }

  render() {
    const templateResult = this.templateFunction({ ...this.state, ...this.props });
    mount(templateResult)
  }

  unMount() {
    componentWillUnMount()
    // TODO: provide a way to unmount the element
    // without setting the innerHTML to ''
    this.actualMointPoint.innerHTML = '';
  }

  mount(templateResult) {
    this.actualMointPoint.innerHTML = templateResult;
    this.componentDidMount()
  }

  componentWillUnMount() {
    // Purpose of the componentWillUnmount() Method
    // Removing event listeners: Detaching event listeners attached to the component
    // -- or its children to prevent memory leaks or unexpected behavior.
    // Canceling ongoing tasks: Aborting ongoing network requests, timers, or other
    // -- asynchronous operations that might continue after the component is gone.
    // Saving data: Preserving user-generated data or component state to local storage or
    // -- a server if needed for later retrieval.
    // Releasing resources: Clearing out data structures or references to prevent memory
    // -- issues, especially for large or complex components.
    // Performing final UI updates: Making any last visual changes or animations before the
    // -- component disappears.
    // Disconnecting from external resources: Closing connections to WebSockets, open
    // -- database connections, or other external resources.
    // Synchronizing data: Ensuring data consistency by updating shared state or notifying
    // -- other components about the component's removal.
  }

  componentDidMount() {
    // Purpose of the componentDidMount() Method
  }

  componentDidRender() {}

  beforeMount() {}
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
