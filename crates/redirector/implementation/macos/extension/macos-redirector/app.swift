// Adapted from mitmproxy_rs (MIT, see LICENSE-mitmproxy).

import NetworkExtension
import OSLog
import SwiftUI
import SystemExtensions

let log = Logger(subsystem: "com.stack1ng.simplehttptap", category: "app")
let networkExtensionIdentifier = "com.stack1ng.simplehttptap.redirector"
/// The argument httptap starts the app with.
let activateArgument = "--activate"

/// The helper app that installs the system extension and starts the transparent proxy, then exits.
///
/// httptap runs it whenever the extension's control socket does not answer; it exits 0 once the proxy runs.
@main
struct App {
    static func main() async throws {
        guard CommandLine.arguments.contains(activateArgument) else {
            exitModal("This helper lets httptap capture the programs it runs. httptap starts it when needed; it does nothing on its own.")
        }
        do {
            try await SystemExtensionInstaller.run()
            try await startProxy()
        } catch {
            FileHandle.standardError.write(Data("httptap redirector: \(error.localizedDescription)\n".utf8))
            exit(1)
        }
        exit(0)
    }

    static func exitModal(_ message: String) -> Never {
        let notification = NSAlert()
        notification.messageText = "httptap"
        notification.informativeText = message
        notification.runModal()
        exit(1)
    }
}

class SystemExtensionInstaller: NSObject, OSSystemExtensionRequestDelegate {
    static func run() async throws {
        let installer = SystemExtensionInstaller()
        try await withCheckedThrowingContinuation { continuation in
            installer.continuation = continuation
            let request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: networkExtensionIdentifier,
                queue: DispatchQueue.main
            )
            request.delegate = installer
            OSSystemExtensionManager.shared.submitRequest(request)
        }
    }

    var continuation: CheckedContinuation<Void, Error>?

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        log.debug("replacing extension \(existing.bundleVersion, privacy: .public) with \(ext.bundleVersion, privacy: .public)")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        FileHandle.standardError.write(Data("httptap redirector: allow the httptap extension in System Settings → General → Login Items & Extensions → Network Extensions\n".utf8))
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        continuation?.resume(throwing: error)
        continuation = nil
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        continuation?.resume()
        continuation = nil
    }
}

/// Saves the transparent proxy's configuration, enabled, and starts it.
func startProxy() async throws {
    let saved = try await NETransparentProxyManager.loadAllFromPreferences()
    let manager = saved.first(where: { manager in
        (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == networkExtensionIdentifier
    }) ?? NETransparentProxyManager()

    let providerProtocol = NETunnelProviderProtocol()
    providerProtocol.providerBundleIdentifier = networkExtensionIdentifier
    providerProtocol.serverAddress = "httptap"

    manager.protocolConfiguration = providerProtocol
    manager.localizedDescription = "httptap"
    manager.isEnabled = true

    try await manager.saveToPreferences()
    // https://stackoverflow.com/a/47569982/934719 - load again before starting the tunnel.
    try await manager.loadFromPreferences()
    if manager.connection.status != .connected && manager.connection.status != .connecting {
        try manager.connection.startVPNTunnel()
    }
}
