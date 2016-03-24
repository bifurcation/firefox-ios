/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import FxA
import Foundation
import Shared
import WebKit

private let log = Logger.syncLogger

protocol U2FHelperDelegate: class {
    func register(u2fHelper: U2FHelper, withData data: [String: String]) // TODO
    func sign(u2fHelper: U2FHelper, withData data: [String: String]) // TODO
}

class OpenSSLToken {
    // TODO
}

class U2FHelper: BrowserHelper {
    weak var delegate: U2FHelperDelegate?
    private weak var browser: Browser?
    
    class func name() -> String {
        return "U2F"
    }
    
    required init(browser: Browser) {
        self.browser = browser
        
        log.debug("Created U2F helper")
        
        if let path = NSBundle.mainBundle().pathForResource("U2F", ofType: "js"), source = try? NSString(contentsOfFile: path, encoding: NSUTF8StringEncoding) as String {
            let userScript = WKUserScript(source: source, injectionTime: WKUserScriptInjectionTime.AtDocumentStart, forMainFrameOnly: true)
            browser.webView!.configuration.userContentController.addUserScript(userScript)
        }
    }
    
    func scriptMessageHandlerName() -> String? {
        return "u2fHandler"
    }
    
    func userContentController(userContentController: WKUserContentController, didReceiveScriptMessage message: WKScriptMessage) {
        let data = message.body as! [String: String]
        
        log.debug("Got U2F call!")
        
        if data["action"] == "register" {
            delegate?.register(self, withData: data)
        }
        
        if data["action"] == "sign" {
            delegate?.sign(self, withData: data)
        }
    }
}
