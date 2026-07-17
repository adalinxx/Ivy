import Testing
@testable import Ivy

@Suite("Post-authentication callback", .serialized)
struct PostIdentifyCallbackTests {
    @Test("didConnect exposes only transcript-authenticated transport metadata")
    func authenticatedMetadata() async throws {
        let serverIdentity = TransportTestHarness.identity("callback-server")
        let clientIdentity = TransportTestHarness.identity("callback-client")
        let serverPort = TransportTestHarness.nextPort()
        let clientPort = TransportTestHarness.nextPort()
        let server = Ivy(config: TransportTestHarness.config(serverIdentity, port: serverPort))
        let client = Ivy(config: TransportTestHarness.config(clientIdentity, port: clientPort))
        let recorder = TransportTestRecorder()
        await server.setTestDelegate(recorder)

        try await server.start()
        try await client.start()
        try await client.connect(to: TransportTestHarness.endpoint(serverIdentity, port: serverPort))
        #expect(try await TransportTestHarness.eventually {
            recorder.authenticatedPeers.count == 1
        })

        let event = recorder.authenticatedPeers.first
        #expect(event?.key == TransportTestHarness.key(clientIdentity))
        #expect(event?.role == .endpoint)
        #expect(event?.route == .direct)
        #expect(event?.metadata == PeerMetadata(
            listenAddresses: [ListenAddress(host: "127.0.0.1", port: clientPort)]))

        await client.stop()
        await server.stop()
    }
}
