/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

(function() {
    "use strict";

    // Only expose the API for secure origins.  Note that malicious code
    // can still send to the webkit.messageHandlers.u2fHandler enpoint
    // anyway, so we will need to guard in Swift as well.
    if (window.location.protocol != "https:") {
        return;
    }

    if (!window.__firefox__) {
        window.__firefox__ = {};
    }

    function sendMessage(obj) {
        webkit.messageHandlers.u2fHandler.postMessage(obj);
    }

    var kActionRegister = "register";
    var kActionSign = "sign";

    var nextRegister = 0;
    var nextSign = 0;
    var callbacks = {};

    window.u2f = {}

    Object.defineProperty(window.u2f, "register", {
        writable: false,
        value: function(appID, registerRequests, registeredKeys, callback, opt_timeoutSeconds) {
            var id = kActionRegister + (nextRegister++);
            callbacks[id] = callback;

            sendMessage({
                action: kActionRegister,
                id: id,
                appID: appID,
                registerRequests: registerRequests,
                registeredKeys: registeredKeys
            });
        }
    });

    Object.defineProperty(window.u2f, "sign", {
        writable: false,
        value: function(appID, challenge, registeredKeys, callback, opt_timeoutSeconds) {
            var id = kActionSign + (nextSign++);
            callbacks[id] = callback;

            sendMessage({
                action: kActionSign,
                id: id,
                appID: appID,
                challenge: challenge,
                registeredKeys: registeredKeys
            });
        }
    });

    window.__firefox__.u2f = {
    finish: function finishRegister(obj) {
        console.log("U2F result: " + JSON.stringify(obj));

        if (!("id" in obj)) {
            console.error("No ID provided in object: " + JSON.stringify(obj));
        } else if (!(obj.id in callbacks)) {
            console.error("Unknown ID: " + obj.id);
            for (id in callbacks) {
                console.error("  Valid ID: " + id);
            }
        }

        if (("id" in obj) && (obj.id in callbacks)) {
            callbacks[obj.id](obj.result);
            delete callbacks[obj.id];
        }
    }
    };
}) ();
