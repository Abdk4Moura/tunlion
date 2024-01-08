// Desc: a route in this context describes subpaths of the url,
// based on a parent route or element,
class Route {
  constructor({ parentElement, childPath, childElement }) {
    // parentElement is required
    if (!parentElement || !(parentElement instanceof HTMLElement)) {
      // throw some error
      console.error('parentPath_or_parentElement not found or not HTMLElement')
      return
    }
    // childElement is required
    if (!childElement || !(childElement instanceof HTMLElement)) {
      // throw some error
      console.error('childElement not found or not HTMLElement')
      return
    }
    // check if parentElement has a mount property
    if (!parentElement.mount) {
      // throw some error
      console.error('parentElement.mount not found')
      return
    }
    if (!parentElement.mount instanceof HTMLElement) {
      // throw some error
      console.error('parentElement.mount is not HTMLElement')
      return
    }
    if (parentElement.mount.contains(childElement)) {
      // throw some error
      console.error(`${childElement} cannot be mounted twice`)
      return
    }
    this.parentElement = parentElement
    this.childPath = childPath
    this.childElement = childElement
    parentElement.mount.appendChild(childElement)
    // change the window url history to reflect the new route
    history.pushState({}, '', `/${window.location.pathname.split('/')[1]}/${childPath}`)
  }

  // remove the childElement from the parentElement
  // and change the window url history to reflect the new route
  // if the childElement is not found, throw an error
  remove() {
    if (this.parentElement.mount.contains(this.childElement)) {
      this.parentElement.mount.removeChild(this.childElement)
      history.pushState({}, '', `/${window.location.pathname.split('/')[1]}`)
    } else {
      // throw some error
      console.error(`${this.childElement} not found`)
      return
    }
  }

  // replace the childElement with a new childElement
  // and change the window url history to reflect the new route
  // if the childElement is not found, throw an error
  // if the new childElement is not found, throw an error
  // if the new childElement is already mounted, throw an error
  // if the new childElement is not an HTMLElement, throw an error
  replace({ newChildPath, newChildElement }) {
    if (this.parentElement.mount.contains(this.childElement)) {
      if (newChildElement && newChildElement instanceof HTMLElement) {
        if (!this.parentElement.mount.contains(newChildElement)) {
          this.parentElement.mount.replaceChild(newChildElement, this.childElement)
          this.childElement = newChildElement
          history.pushState({}, '', `/${window.location.pathname.split('/')[1]}/${newChildPath}`)
        } else {
          // throw some error
          console.error(`${newChildElement} cannot be mounted twice`)
          return
        }
      } else {
        // throw some error
        console.error('newChildElement not found or not HTMLElement')
        return
      }
    } else {
      // throw some error
      console.error(`${this.childElement} not found`)
      return
    }
  }
}
