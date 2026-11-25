import Foundation
import NetworkExtension
import OSLog

let log = Logger(subsystem: "com.stack1ng.simplehttptap", category: "extension")

autoreleasepool {
    let version = Bundle.main.infoDictionary!["CFBundleShortVersionString"] as! String
    log.info("starting httptap redirector \(version, privacy: .public) system extension")
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
