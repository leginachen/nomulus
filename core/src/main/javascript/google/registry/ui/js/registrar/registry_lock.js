// Copyright 2020 The Nomulus Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

goog.provide('registry.registrar.RegistryLock');

goog.forwardDeclare('registry.registrar.Console');
goog.require('goog.array');
goog.require('goog.dom');
goog.require('goog.dom.classlist');
goog.require('goog.events');
goog.require('goog.events.KeyCodes');
goog.require('goog.events.EventType');
goog.require('goog.json');
goog.require('goog.net.XhrIo');
goog.require('goog.soy');
goog.require('registry.Resource');
goog.require('registry.ResourceComponent');
goog.require('registry.soy.registrar.registrylock');


/**
 * Registry Lock page, allowing the user to lock / unlock domains.
 * @param {!registry.registrar.Console} console
 * @param {!registry.Resource} resource the RESTful resource for the registrar.
 * @constructor
 * @extends {registry.ResourceComponent}
 * @final
 */
registry.registrar.RegistryLock = function(console, resource) {
  registry.registrar.RegistryLock.base(
      this, 'constructor', console, resource,
      registry.soy.registrar.registrylock.settings, false, null);
};
goog.inherits(registry.registrar.RegistryLock, registry.ResourceComponent);

registry.registrar.RegistryLock.prototype.runAfterRender = function(objArgs) {
  this.isAdmin = objArgs.isAdmin;
  this.clientId = objArgs.clientId;
  this.xsrfToken = objArgs.xsrfToken;

  if (objArgs.registryLockAllowed) {
    // Load the existing locks and display them in the table
    goog.net.XhrIo.send(
        '/registry-lock-get?clientId=' + objArgs.clientId, e => this.fillLocksPage_(e));
  } else {
    goog.soy.renderElement(
        goog.dom.getRequiredElement('locks-content'),
        registry.soy.registrar.registrylock.lockNotAllowedOnRegistrar);
  }
};

/**
 * Removes the lock/unlock-confirmation modal if it exists
 * @private
 */
const removeModalIfExists_ = function() {
  var modalElement = goog.dom.getElement('lock-confirm-modal');
  if (modalElement != null) {
    modalElement.parentElement.removeChild(modalElement);
  }
}

/**
 * Clears the modal and displays the locks content (lock a new domain, existing locks) that was
 * retrieved from the server.
 * @private
 */
registry.registrar.RegistryLock.prototype.fillLocksPage_ = function(e) {
  var response =
      /** @type {!registry.json.locks.ExistingLocksResponse} */
      (e.target.getResponseJson(registry.Resource.PARSER_BREAKER_));
  if (response.status === 'SUCCESS') {
    removeModalIfExists_();
    var locksDetails = response.results[0]
    var locksContentDiv = goog.dom.getRequiredElement('locks-content');
    goog.soy.renderElement(
        locksContentDiv,
        registry.soy.registrar.registrylock.locksContent,
        {locks: locksDetails.locks,
            email: locksDetails.email,
            lockEnabledForContact: locksDetails.lockEnabledForContact});

    if (locksDetails.lockEnabledForContact) {
      this.registryLockEmailAddress = locksDetails.email;
      // Listen to the lock-domain 'submit' button click
      var lockButton = goog.dom.getRequiredElement('button-lock-domain');
      goog.events.listen(lockButton, goog.events.EventType.CLICK, this.onLockDomain_, false, this);
      // For all unlock buttons, listen and perform the unlock action if they're clicked
      var unlockButtons = goog.dom.getElementsByClass('domain-unlock-button', locksContentDiv);
      unlockButtons.forEach(button =>
        goog.events.listen(button, goog.events.EventType.CLICK, this.onUnlockDomain_, false, this));
    }
  } else {
    var errorDiv = goog.dom.getRequiredElement('modal-error-message');
    errorDiv.textContent = response.message;
    errorDiv.removeAttribute('hidden');
  }
}

/**
 * Shows the lock/unlock confirmation modal
 * @private
 */
registry.registrar.RegistryLock.prototype.showModal_ = function(targetElement, domain, isLock) {
  var parentElement = targetElement.parentElement;
  // attach the modal to the parent element so focus remains correct if the user closes the modal
  var modalElement = goog.soy.renderAsElement(
      registry.soy.registrar.registrylock.confirmModal,
      {domain: domain,
          isLock: isLock,
          isAdmin: this.isAdmin,
          emailAddress: this.registryLockEmailAddress});
  parentElement.prepend(modalElement);
  if (domain == null) {
    goog.dom.getRequiredElement('domain-lock-input-value').focus();
  } else {
    var passwordElem = goog.dom.getElement('domain-lock-password');
    if (passwordElem != null) {
      passwordElem.focus();
    }
  }
  // delete the modal when the user clicks the cancel button
  goog.events.listen(
      goog.dom.getRequiredElement('domain-lock-cancel'),
      goog.events.EventType.CLICK,
      removeModalIfExists_,
      false,
      this);

  // Listen to the "submit" click and also the user hitting enter
  goog.events.listen(
      goog.dom.getRequiredElement('domain-lock-submit'),
      goog.events.EventType.CLICK,
      e => this.lockOrUnlockDomain_(isLock, e),
      false,
      this);

  [goog.dom.getElement('domain-lock-password'),
      goog.dom.getElement('domain-lock-input-value')].forEach(elem => {
        if (elem != null) {
          goog.events.listen(
              elem,
              goog.events.EventType.KEYPRESS,
              e => {
                if (e.keyCode === goog.events.KeyCodes.ENTER) {
                  this.lockOrUnlockDomain_(isLock, e);
                }
              },
              false,
              this);
        }
      });
}

/**
 * Locks or unlocks the specified domain
 * @private
 */
registry.registrar.RegistryLock.prototype.lockOrUnlockDomain_ = function(isLock, e) {
  var domain = goog.dom.getRequiredElement('domain-lock-input-value').value;
  var passwordElem = goog.dom.getElement('domain-lock-password');
  var password = passwordElem == null ? null : passwordElem.value;
  var relockDuration = this.getRelockDurationFromModal_()
  goog.net.XhrIo.send('/registry-lock-post',
      e => this.fillLocksPage_(e),
      'POST',
      goog.json.serialize({
        'registrarId': this.clientId,
        'domainName': domain,
        'isLock': isLock,
        'password': password,
        'relockDurationMillis': relockDuration
      }), {
        'X-CSRF-Token': this.xsrfToken,
        'Content-Type': 'application/json; charset=UTF-8'
      });
}

/**
 * Returns the duration after which we will re-lock a locked domain. Will return null if we
 * are locking a domain, or if the user selects the "Never" option
 * @private
 */
registry.registrar.RegistryLock.prototype.getRelockDurationFromModal_ = function() {
  var inputElements = goog.dom.getElementsByTagNameAndClass("input", "relock-duration-input");
  for (var i = 0; i < inputElements.length; i++) {
    var elem = inputElements[i];
    if (elem.checked && elem.value !== "0") {
      return elem.value;
    }
  }
  return null;
}

/**
 * Click handler for unlocking domains (button click).
 * @private
 */
registry.registrar.RegistryLock.prototype.onUnlockDomain_ = function(e) {
  // the domain is stored in the button ID if it's the right type of button
  var idRegex = /button-unlock-(.*)/
  var targetId = e.target.id;
  var match = targetId.match(idRegex);
  if (match) {
    var domain = match[1];
    this.showModal_(e.target, domain, false);
  }
}

/**
 * Click handler for lock-domain button.
 * @private
 */
registry.registrar.RegistryLock.prototype.onLockDomain_ = function(e) {
  this.showModal_(e.target, null, true);
};
