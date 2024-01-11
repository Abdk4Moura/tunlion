// const defaultMountOptions = {
//   replaceElemP: false,
// }

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

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

// StateNotifier class
// Usage: let stateNotifier = new StateNotifier({ hasSelectedFile: false, hasReceivedFileInfo: false });
export class StateNotifier {
  static #instance = null;

  static getInstance(initialState) {
    if (!StateNotifier.#instance) {
      StateNotifier.#instance = new StateNotifier(initialState);
    }
    return StateNotifier.#instance;
  }

  constructor(initialState) {
    this._state = initialState;
    this.listeners = [];
  }

  get state() {
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
  setPlaceholderId() { this._placeholderId = `elem${Math.random().toString(36).substring(7)}` };

  get randomId() {
    return this._placeholderId
  }

  _placeholderId = null;
  _hasInitialised = false;

  constructor({ mountPoint, mountOptions, initProps, templateFunction }) {
    // can also use new.target
    assert(this.constructor.name !== '_Element', 'Cannot instantiate abstract class')
    // mountPoint is compulsory when mountOptions is provided
    if (xor(mountPoint, mountOptions)) {
      assert(mountPoint, 'mountPoint must be provided when mountOptions is provided')
    }
    if (mountOptions) {
      assert(typeof mountOptions === 'object', 'mountOptions must be an object')
    }

    switch (new.target) {
      case GenericElement:
        assert(initProps, 'initProps must be provided')
        assert(!!initProps.stateProps, 'initProps must contain stateProps')
        break;
    }
    assert(templateFunction, 'templateFunction must be provided')

    this.mountPoint = null
    this.childrenSlot = null
    this.templateExists = !mountPoint

    this.decideMountPointAndChildren({ mountPoint, mountOptions })

    this.templateFunction = templateFunction.bind(this);
    this._props = initProps;
  }

  decideMountPointAndChildren({ mountPoint, mountOptions }) {
    if (mountOptions) {
      const { replaceElemP } = mountOptions;
      this.mountPoint = document.createElement('div');
      if (replaceElemP) {
        mountPoint.parentElement.replaceChild(this.mountPoint, mountPoint);
      } else {
        // add this::mountPoint to the DOM under mountPoint
        mountPoint.appendChild(this.mountPoint);
      }
      this.childrenSlot = document.createElement('div');
      this.childrenSlot.classList.add('genericElemSlot');
      this.mountPoint.appendChild(this.childrenSlot);
    }
    // if (!mountPoint) {
    // mountPoint is null is just a reassertion, it was
    // already stated in the constructor
    // this.mountPoint will be later set by useSelectorMapping
    // return;
    // }
  }

  // TODO: Implement a pub/sub pattern for state changes
  willMount() {}

  appendChild(child) {
    assert(child instanceof HTMLElement, 'child must be an HTMLElement')
    if (this.isSingletonElement) {
      throw new Error('Cannot append child to singleton element');
    }
    this.childrenSlot.appendChild(child);
  }

  useSelectorMapping(mapping) {
    assert(typeof mapping === 'object' || typeof mapping === Map, 'mapping must be an `object` or `Map`')
    assert(mapping.hasOwnProperty('root'), 'mapping must contain a `root` key')
    if (!this._hasInitialised) {
      assert(!this.mountPoint, 'mountPoint cannot be initially defined when template exists')
    }

    // now assign mountPoint
    this.mountPoint = document.querySelector(mapping.root);

    for (const selector of Object.keys(mapping)) {
      const potentialPlaceholder = mapping[selector];
      if (selector === 'root') {
        continue
      }

      if (potentialPlaceholder instanceof Placeholder) {
        switch (potentialPlaceholder.type) {
          case Types.ATTR:
            for (const attr of Object.keys(potentialPlaceholder.value)) {
              let value = potentialPlaceholder.value[attr];
              this.mountPoint.querySelector(selector).setAttribute(attr, value);
            }
            break;
          case Types.INNER_HTML:
            this.mountPoint.querySelector(selector).innerHTML = potentialPlaceholder.value;
            break;
          case Types.CHILDREN:
            for (const child of potentialPlaceholder.value) {
              this.mountPoint.querySelector(selector).appendChild(child);
            }
            break;
        }
        continue
      }
      this.mountPoint.querySelector(selector).innerHTML = potentialPlaceholder;
    }
  }

  // docstring
  // children: array of elements
  //
  appendChildren(children) {
    if (this.isSingletonElement) {
      throw new Error('Cannot append child to singleton element');
    }
    children.forEach((child) => this.childrenSlot.appendChild(child));
  }

  get children() {
    return this.childrenSlot.children;
  }

  set children(children) {
    if (this.isSingletonElement) {
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
    if (!this._hasInitialised) {
      this._updateInitial(); // Function for initial setup
      this._hasInitialised = true;
      return
    } else {
      this._updateOnStateChange(); // Function for subsequent updates
    }
  }

  _updateInitial() {
    // Perform initial setup actions here
    this.willMount();
    this.renderComponent();
    this.componentDidRender();
  }

  _updateOnStateChange() {
    // Perform actions for state changes here
    this.unMount();
    this.renderComponent();
    this.componentDidRender();
  }

  // just an alias
  render() {
    return this.update()
  }

  renderComponent() {
    const templateResult = this.templateFunction({ ...this.state, ...this.props });
    this.mount(templateResult)
  }

  unMount() {
    this.componentWillUnMount()
    // TODO: provide a way to unmount the element
    // without setting the innerHTML to ''
    if (!this.templateExists) {
      this.mountPoint.innerHTML = '';
      return
    }
    // create a new element with the same tag name
    // and replace the old one
    const placeholderElement = document.createElement(this.mountPoint.tagName);
    // newElem's id should be some random id which this component knows
    // so that it can be used to replace the element in the DOM
    this.setPlaceholderId()
    placeholderElement.id = this.randomId;
    placeholderElement.style.display = 'none';
    this.mountPoint.parentElement.replaceChild(placeholderElement, this.mountPoint);
  }

  mount(templateResult) {
    if (this.templateExists) {
      this._mountOnExistingTemplate(templateResult)
    } else {
      this._mountOnNewTemplate(templateResult)
    }
    this.componentDidMount()
  }

  _mountOnExistingTemplate(templateResult) {
    if (!this._hasInitialised) {
      this._mountInitialForExisingTemplate(templateResult)
      this._hasInitialised = true
      return
    }
    this._mountOnStateChangeForExistingTemplate(templateResult)
  }

  _mountInitialForExisingTemplate(templateResult) {
    this.useSelectorMapping(templateResult);
  }

  _mountOnStateChangeForExistingTemplate(templateResult) {
    // remount actualMointPoint
    let placeholderElement = document.getElementById(this.randomId);
    placeholderElement.parentElement.replaceChild(this.mountPoint, placeholderElement);
    this.useSelectorMapping(templateResult);
  }

  _mountOnNewTemplate(templateResult) {
    if (!this._hasInitialised) {
      this._mountInitialForNewTemplate(templateResult)
      this._hasInitialised = true
      return
    }
    this._mountOnStateChangeForNewTemplate(templateResult)
  }

  _mountInitialForNewTemplate(templateResult) {
    this.mountPoint.innerHTML = templateResult;
  }

  _mountOnStateChangeForNewTemplate(templateResult) {
    this.mountPoint.innerHTML = templateResult;
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
  }

  get state() {
    return this._state;
  }

  set state(newState) {
    this.throwIfInvalidState(newState);
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
    const prevState = { ...this.state };

    this.throwIfInvalidState(newState);
    this.state = { ...this.state, ...newState };

    // Check if any state property has changed
    if (!this.areStatesEqual(prevState, this.state)) {
      this.update();
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
}

export class NotifiedElement extends _Element {
  constructor({ mountPoint, mountOptions, initProps, templateFunction, stateNotifier }) {
    assert(stateNotifier, 'stateNotifier must be provided')
    assert(stateNotifier instanceof StateNotifier, 'stateNotifier must be an instance of StateNotifier')

    super({ mountPoint, mountOptions, initProps, templateFunction });
    stateNotifier.addListener(
      this.update
    );
    this.stateNotifier = stateNotifier;

    this.willMount();
    this.update();
  }
}

function xor(a, b) {
  return (a || b) && !(a && b);
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
