export const Types = {
  ATTR: 'attr',
  INNER_HTML: 'innerHTML',
  CHILDREN: 'children',
}

export class Placeholder {
  constructor(type, value) {
    switch (type) {
      case Types.ATTR:
        if (typeof value !== 'object') {
          throw new Error('Value must be an object');
        }
    }
    this.type = type;
    this.value = value;
  }
}

// StateNotifier class
// Usage: let stateNotifier = new StateNotifier({ hasSelectedFile: false, hasReceivedFileInfo: false });
export class StateNotifier {
  // TODO: Use the singleton pattern to ensure that only one instance of the class is created
  // for a specific state
  // #instance = null;

  // static getInstance(initialState) {
  //   if (!StateNotifier.#instance) {
  //     StateNotifier.#instance = new StateNotifier(initialState);
  //   }
  //   return StateNotifier.instance;
  // }

  constructor(initialState) {
    this._state = initialState;
    this.listeners = [];
  }

  get set() {
    return this._state;
  }

  /**
   * @param {object} newState
   */
  set state(newState) {
    this._state = { ...this._state, ...newState };
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

// _Element is an abstract class with no concept of state
class _Element {
  randomId = `elem${Math.random().toString(36).substring(7)}`;

  constructor({ mountPoint, mountOptions, initProps, templateFunction }) {
    const { replaceElemInMountPoint, templateAlreadyExistent } = mountOptions;

    let mainElem;
    if (!templateAlreadyExistent) {
      if (!replaceElemInMountPoint) {
        mainElem = mountPoint;
      } else {
        mainElem = document.createElement('div');
        mountPoint.parentNode.replaceChild(mainElem, mountPoint);
      }
      this._replaceElemInMountPoint = true;
    }
    const childrenSlot = mainElem.querySelector('div.genericElemSlot')
    this.childrenSlot = childrenSlot;
    this.templateAlreadyExistent = templateAlreadyExistent;

    this.actualMointPoint = mainElem;
    this.templateFunction = templateFunction.bind(this);
  }

  appendChild(child) {
    if (isSingletonElement) {
      throw new Error('Cannot append child to singleton element');
    }
    this.childrenSlot.appendChild(child);
  }

  useSelectorMapping(mapping) {
    for (const selector in Object.keys(mapping)) {
      const value = mapping[selector];

      if (value instanceof Placeholder) {
        switch (value.type) {
          case Types.ATTR:
            for (const attr in Object.keys(value)) {
              this.actualMointPoint.querySelector(selector).setAttribute(attr);
            }
            break;
          case Types.INNER_HTML:
            this.actualMointPoint.querySelector(selector).innerHTML = value;
            break;
          case Types.CHILDREN:
            for (const child of value) {
              this.actualMointPoint.querySelector(selector).appendChild(child);
            }
            break;
        }
      } else {
        this.actualMointPoint.querySelector(selector).innerHTML = value;
      }
    }
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

  update() {
    // will run only once
    beforeMount();
    unMount();
    renderComponent();
    componentDidRender();

    // will run every time the state changes
    this.update = function () {
      unMount()
      renderComponent()
      componentDidRender()
    }
  }

  render() {
    return update()
  }

  renderComponent() {
    const templateResult = this.templateFunction({ ...this.state, ...this.props });
    mount(templateResult)
  }

  unMount() {
    componentWillUnMount()
    // TODO: provide a way to unmount the element
    // without setting the innerHTML to ''
    if (!this.templateAlreadyExistent) {
      this.actualMointPoint.innerHTML = '';
      return
    }
    // create a new element with the same tag name
    // and replace the old one
    const newElem = document.createElement(this.actualMointPoint.tagName);
    // newElem's id should be some random id which this component knows
    // so that it can be used to replace the element in the DOM
    newElem.id = this.randomId;
    newElem.style.display = 'none';
    this.actualMointPoint.parent.replaceChild(newElem, this.actualMointPoint);
  }

  mount(templateResult) {
    if (!this.templateAlreadyExistent) {
      this.actualMointPoint.innerHTML = templateResult;
    } else {
      // remount actualMointPoint
      let newElem = document.getElementById(this.randomId);
      newElem.parentNode.replaceChild(this.actual, newElem);
      this.useSelectorMapping(templateResult);
    }
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

export class GenericElement extends _Element {
  constructor({ mountPoint, mountOptions, initProps, templateFunction }) {
    super({ mountPoint, mountOptions, initProps, templateFunction });

    // state and props
    this._state = initProps.stateProps;
    this.props = initProps.props;
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
}

export class NotifiedElement extends _Element {
  constructor({ mountPoint, mountOptions, initProps, templateFunction, stateNotifier }) {
    super({ mountPoint, mountOptions, initProps, templateFunction });
    stateNotifier.addListener(
      this.update
    );
    this.stateNotifier = stateNotifier;

    beforeMount();
    update();
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
