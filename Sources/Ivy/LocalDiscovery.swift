#if canImport(Network)
@preconcurrency import Network
import Foundation

final class LocalDiscovery: Sendable {
    let serviceType: String
    let port: UInt16
    let publicKey: String
    nonisolated(unsafe) private var browser: NWBrowser?
    nonisolated(unsafe) private var listener: NWListener?
    private let queue = DispatchQueue(label: "ivy.discovery")
    private let onPeerFound: @Sendable (PeerEndpoint) -> Void

    init(serviceType: String, port: UInt16, publicKey: String, onPeerFound: @escaping @Sendable (PeerEndpoint) -> Void) {
        self.serviceType = serviceType
        self.port = port
        self.publicKey = publicKey
        self.onPeerFound = onPeerFound
    }

    func startAdvertising() {
        let listener = try? NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: port)!)
        listener?.service = NWListener.Service(
            name: publicKey.prefix(16).description,
            type: serviceType,
            txtRecord: NWTXTRecord(["pk": publicKey, "port": "\(port)"])
        )
        listener?.stateUpdateHandler = { _ in }
        listener?.newConnectionHandler = { _ in }
        listener?.start(queue: queue)
        self.listener = listener
    }

    func startBrowsing() {
        let descriptor = NWBrowser.Descriptor.bonjour(type: serviceType, domain: nil)
        let browser = NWBrowser(for: descriptor, using: .tcp)
        browser.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self else { return }
            for result in results {
                if case .service = result.endpoint,
                   case let .bonjour(record) = result.metadata {
                    if let pk = record["pk"], let portStr = record["port"], let port = UInt16(portStr) {
                        if pk != self.publicKey {
                            self.onPeerFound(PeerEndpoint(publicKey: pk, host: result.endpoint.debugDescription, port: port))
                        }
                    }
                }
            }
        }
        browser.start(queue: queue)
        self.browser = browser
    }

    func stop() {
        browser?.cancel()
        listener?.cancel()
        browser = nil
        listener = nil
    }
}
#endif
