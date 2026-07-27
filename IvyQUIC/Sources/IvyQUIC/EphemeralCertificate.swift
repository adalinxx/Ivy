import Crypto
import Foundation
import SwiftASN1
import X509

/// A self-signed certificate written to disk for the QUIC TLS handshake.
///
/// This key is *not* the Ivy identity key and proves nothing about the peer:
/// QUIC's TLS layer supplies confidentiality only, and identity remains bound by
/// the Ed25519 signed session handshake (IVY-003). Peers therefore accept any
/// certificate, so a fresh throwaway one per process is enough.
struct EphemeralCertificate {
    let certificateChainPath: String
    let privateKeyPath: String
    private let directory: URL

    init() throws {
        let key = P256.Signing.PrivateKey()
        let certificateKey = Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("ivy") }
        let now = Date()
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: certificateKey.publicKey,
            notValidBefore: now.addingTimeInterval(-60),
            notValidAfter: now.addingTimeInterval(60 * 60 * 24 * 365),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                try ExtendedKeyUsage([.serverAuth, .clientAuth])
            },
            issuerPrivateKey: certificateKey)

        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("ivy-quic-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        certificateChainPath = directory.appendingPathComponent("cert.pem").path
        privateKeyPath = directory.appendingPathComponent("key.pem").path
        try certificate.serializeAsPEM().pemString
            .write(toFile: certificateChainPath, atomically: true, encoding: .utf8)
        try certificateKey.serializeAsPEM().pemString
            .write(toFile: privateKeyPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: privateKeyPath)
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }
}
