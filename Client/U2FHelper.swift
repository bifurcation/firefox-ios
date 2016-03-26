/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import FxA
import Foundation
import Shared
import WebKit
import LocalAuthentication
import Sync
import SwiftKeychainWrapper

private let log = Logger.syncLogger

// XXX: Localization?
private let kAuthenticationReason: String = "Authenticate with U2F"

// These must be kept in sync with U2F.js
private let kActionRegister: String = "register"
private let kActionSign: String = "sign"
private let kTagID: String = "id"
private let kTagAction: String = "action"

private let kMasterKeyName = "org.mozilla.u2f.master_key"

// This must be kept in sync with KeyBundle.swift
private let kMasterEncKeyLength: Int = 44 // 32 bytes in Base64

enum U2FErrorCode: Int {
    case OK = 0
    case OTHER_ERROR = 1
    case BAD_REQUEST = 2
    case CONFIGURATION_UNSUPPORTED = 3
    case DEVICE_INELIGIBLE = 4
    case TIMEOUT = 5
}

protocol U2FResponse {
    func toJSON() -> String?
}

struct U2FRegisterRequest {
    var version: String
    var challenge: String
    var appId: String

    init?(obj: AnyObject) {
        guard let dict = obj as? [String:String] else { return nil }
        guard let version = dict["version"] as String? else { return nil }
        guard let challenge = dict["challenge"] as String? else { return nil }
        guard let appId = dict["appId"] as String? else { return nil }

        self.version = version
        self.challenge = challenge
        self.appId = appId
    }
}

struct U2FRegisterResponse: U2FResponse {
    var registrationData : String
    var clientData: String

    func toJSON() -> String? {
        let value: [String:String] = [
            "registrationData": self.registrationData,
            "clientData": self.clientData
        ]
        let data = try! NSJSONSerialization.dataWithJSONObject(value, options: .PrettyPrinted)
        return NSString(data: data, encoding: NSUTF8StringEncoding) as String?
    }
}

struct U2FSignRequest {
    var version: String
    var challenge: String
    var keyHandle: String
    var appId: String

    init?(obj: AnyObject) {
        guard let dict = obj as? [String:String] else { return nil }
        guard let version = dict["version"] as String? else { return nil }
        guard let challenge = dict["challenge"] as String? else { return nil }
        guard let keyHandle = dict["keyHandle"] as String? else { return nil }
        guard let appId = dict["appId"] as String? else { return nil }

        self.version = version
        self.challenge = challenge
        self.keyHandle = keyHandle
        self.appId = appId
    }
}

struct U2FSignResponse: U2FResponse {
    var keyHandle: String
    var signatureData: String
    var clientData: String

    func toJSON() -> String? {
        let value: [String:String] = [
            "keyHandle": self.keyHandle,
            "signatureData": self.signatureData,
            "clientData": self.clientData
        ]
        let data = try! NSJSONSerialization.dataWithJSONObject(value, options: .PrettyPrinted)
        return NSString(data: data, encoding: NSUTF8StringEncoding) as String?
    }
}

struct U2FErrorResponse: U2FResponse {
    var errorCode: U2FErrorCode
    var errorMessage: String?

    func toJSON() -> String? {
        var value: [String:AnyObject] = [
            "errorCode": self.errorCode.rawValue
        ]
        if self.errorMessage != nil {
            value["errorMessage"] = self.errorMessage
        }
        let data = try! NSJSONSerialization.dataWithJSONObject(value, options: .PrettyPrinted)
        return NSString(data: data, encoding: NSUTF8StringEncoding) as String?
    }
}

@available(iOS 9, *)
struct U2FDOMRequest {
    var origin: WKSecurityOrigin
    var action: String
    var id: String
    var registerRequests: [U2FRegisterRequest]
    var signRequests: [U2FSignRequest]

    init?(message: WKScriptMessage) {
        log.debug("Entered U2FDOMRequest.init?()")

        self.origin = message.frameInfo.securityOrigin
        self.action = ""
        self.id = ""

        guard let data = message.body as? [String: AnyObject] else {
            log.debug("Could not convert object to [String:AnyObject]")
            return nil
        }

        guard let id = data[kTagID] as? String else {
            log.debug("Could not capture id")
            return nil
        }
        guard let action = data[kTagAction] as? String else {
            log.debug("Could not capture action")
            return nil
        }
        self.id = id
        self.action = action

        self.registerRequests = [U2FRegisterRequest]()
        if let regRequests = data["registerRequests"] as? [AnyObject] {
            for req in regRequests {
                guard let regReq = U2FRegisterRequest(obj: req) else { continue }
                self.registerRequests.append(regReq)
            }
        }

        self.signRequests = [U2FSignRequest]()
        if let sigRequests = data["signRequests"] as? [AnyObject] {
            for req in sigRequests {
                guard let sigReq = U2FSignRequest(obj: req) else { continue }
                self.signRequests.append(sigReq)
            }
        }
    }
}

// The delegate just facilitates UI interactions and communications 
// with content in the WKWebView
@available(iOS 9, *)
protocol U2FHelperDelegate: class {
    func u2fFinish(id id: String, response: U2FResponse)
}

class OpenSSLToken {
    // TODO
}


@available(iOS 9, *)
class U2FHelper: BrowserHelper {
    weak var delegate: U2FHelperDelegate?
    private weak var browser: Browser?
    
    class func name() -> String {
        return "U2F"
    }
    
    required init(browser: Browser) {
        self.browser = browser

        if let path = NSBundle.mainBundle().pathForResource("U2F", ofType: "js"), source = try? NSString(contentsOfFile: path, encoding: NSUTF8StringEncoding) as String {
            let userScript = WKUserScript(source: source, injectionTime: WKUserScriptInjectionTime.AtDocumentStart, forMainFrameOnly: true)
            browser.webView!.configuration.userContentController.addUserScript(userScript)
        }
    }
    
    func scriptMessageHandlerName() -> String? {
        return "u2fHandler"
    }

    private func register(request: U2FDOMRequest, withMasterKeyBundle keys: KeyBundle) -> U2FResponse {
        return U2FErrorResponse(
            errorCode: .CONFIGURATION_UNSUPPORTED,
            errorMessage: "Register method unimplemented \(request.registerRequests.count) \(request.signRequests.count)"
        )
    }

    private func sign(request: U2FDOMRequest, withMasterKeyBundle keys: KeyBundle) -> U2FResponse {
        return U2FErrorResponse(
            errorCode: .CONFIGURATION_UNSUPPORTED,
            errorMessage: "Sign method unimplemented \(request.registerRequests.count) \(request.signRequests.count)"
        )
    }

    func userContentController(userContentController: WKUserContentController, didReceiveScriptMessage message: WKScriptMessage) {
        log.debug("Got U2F call")

        guard let request = U2FDOMRequest(message: message) else {
            log.debug("Could not deserialize request")
            guard let dict = message.body as? [String:AnyObject] else {
                log.debug("Couldn't convert body to dictionary")
                return
            }

            guard let id = dict["id"] as? String else {
                log.debug("Couldn't convert body to dictionary")
                return
            }

            delegate?.u2fFinish(id: id, response: U2FErrorResponse(errorCode: .BAD_REQUEST, errorMessage: "BadRequest"))
            return
        }

        // Reject requests from non-HTTPS origins
        // U2F.js doesn't present the API, but
        if request.origin.`protocol` != "https" {
            delegate?.u2fFinish(id: request.id, response: U2FErrorResponse(errorCode: .BAD_REQUEST, errorMessage: "U2F is only supported on HTTPS origins"))
        }

        // Display the TouchID prompt
        // We manage the TouchID prompt ourselves (instead of using, say AppAuthenticator)
        // because we really want it to appear on every call.
        let context = LAContext()
        let policy = LAPolicy.DeviceOwnerAuthenticationWithBiometrics
        let unauthenticatedError = U2FErrorResponse(errorCode: .OTHER_ERROR, errorMessage: "Unauthenticated")
        if (context.canEvaluatePolicy(policy, error: nil)) {
            context.evaluatePolicy(policy, localizedReason: kAuthenticationReason, reply:{ authenticated, error in
                log.debug("Authentication result: \(authenticated) \(error)")
                if !authenticated {
                    self.delegate?.u2fFinish(id: request.id, response: unauthenticatedError)
                    return
                }

                self.performU2FAction(authenticated, data: request)
            })
        } else {
            self.delegate?.u2fFinish(id: request.id, response: unauthenticatedError)
        }
    }

    func performU2FAction(authenticated: Bool, data: U2FDOMRequest) {

        // Fetch or generate the master key
        var keys: KeyBundle
        if KeychainWrapper.hasValueForKey(kMasterKeyName) {
            let keyData = KeychainWrapper.stringForKey(kMasterKeyName)!
            log.debug("Fetched key data: \(keyData)")
            let split = keyData.startIndex.advancedBy(kMasterEncKeyLength)
            let enc = keyData.substringToIndex(split)
            let mac = keyData.substringFromIndex(split)
            keys = KeyBundle(encKeyB64: enc, hmacKeyB64: mac)
        } else {
            keys = KeyBundle.random()
            let rawKeys = keys.asPair()
            let totalKey = rawKeys[0] + rawKeys[1]
            log.debug("Generated key data: \(totalKey)")
            KeychainWrapper.setString(totalKey, forKey: kMasterKeyName)
        }

        // Perform the required action
        var response: U2FResponse
        switch data.action {
        case kActionRegister:
            log.debug("U2F register")
            response = register(data, withMasterKeyBundle: keys)
        case kActionSign:
            log.debug("U2F sign")
            response = sign(data, withMasterKeyBundle: keys)
        default:
            log.debug("Unknown action")
            response = U2FErrorResponse(errorCode: .OTHER_ERROR, errorMessage: "Internal error")
        }

        // Have the delegate return the result to JS
        delegate?.u2fFinish(id: data.id, response: response)
    }
}
