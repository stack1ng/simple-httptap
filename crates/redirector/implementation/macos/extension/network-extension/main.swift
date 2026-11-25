import Foundation
import NetworkExtension
import OSLog

let log = Logger(subsystem: "com.stack1ng.simplehttptap", category: "extension")
let networkExtensionIdentifier = "com.stack1ng.simplehttptap.redirector"

autoreleasepool {
    let version = Bundle.main.infoDictionary!["CFBundleShortVersionString"] as! String
    log.error("starting httptap redirector \(version, privacy: .public) system extension")
    log.debug("debug-level logging active")
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
