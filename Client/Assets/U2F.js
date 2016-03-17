/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

(function() {
    "use strict";
    
    if (!window.__firefox__) {
        window.__firefox__ = {};
    }
    
    function sendMessage(action) {
        webkit.messageHandlers.u2fHandler.postMessage({action: action});
    }
    
    window.u2f = {
        register: function() {
            sendMessage("register");
        },
        
        sign: function() {
            sendMessage("sign");
        }
    }
    
    window.__firefox__.finishRegister = function () {
        alert("DID REGISTER");
    };
    
    window.__firefox__.finishSign = function () {
        alert("DID SIGN");
    };
    
}) ();
