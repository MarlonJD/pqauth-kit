import Foundation

#if compiler(>=6.3) && canImport(CryptoKit)
import CryptoKit

@available(iOS 26.0, macOS 26.0, *)
public struct CryptoKitMLDSA65Provider: PQAuthProvider {
    public let metadata: PQAuthProviderMetadata

    public init(platform: PQAuthPlatform) {
        self.metadata = PQAuthProviderCatalog.apple(platform: platform)
            .providers
            .first { $0.providerId.contains("cryptokit.mldsa65") }!
    }

    public func generateKeyPair() throws -> PQAuthKeyPair {
        let privateKey = try MLDSA65.PrivateKey()
        return PQAuthKeyPair(
            publicKey: privateKey.publicKey.rawRepresentation,
            privateKey: privateKey.integrityCheckedRepresentation
        )
    }

    public func sign(_ signedBytes: Data, context: Data, privateKey: Data) throws -> Data {
        let key = try MLDSA65.PrivateKey(integrityCheckedRepresentation: privateKey)
        return try key.signature(for: signedBytes, context: context)
    }

    public func verify(signature: Data, signedBytes: Data, context: Data, publicKey: Data) throws -> Bool {
        try validate(signature: signature, publicKey: publicKey)
        let key = try MLDSA65.PublicKey(rawRepresentation: publicKey)
        return key.isValidSignature(signature, for: signedBytes, context: context)
    }
}

@available(iOS 26.0, macOS 26.0, *)
public struct CryptoKitMLDSA87Provider: PQAuthProvider {
    public let metadata: PQAuthProviderMetadata

    public init(platform: PQAuthPlatform) {
        self.metadata = PQAuthProviderCatalog.apple(platform: platform)
            .providers
            .first { $0.providerId.contains("cryptokit.mldsa87") }!
    }

    public func generateKeyPair() throws -> PQAuthKeyPair {
        let privateKey = try MLDSA87.PrivateKey()
        return PQAuthKeyPair(
            publicKey: privateKey.publicKey.rawRepresentation,
            privateKey: privateKey.integrityCheckedRepresentation
        )
    }

    public func sign(_ signedBytes: Data, context: Data, privateKey: Data) throws -> Data {
        let key = try MLDSA87.PrivateKey(integrityCheckedRepresentation: privateKey)
        return try key.signature(for: signedBytes, context: context)
    }

    public func verify(signature: Data, signedBytes: Data, context: Data, publicKey: Data) throws -> Bool {
        try validate(signature: signature, publicKey: publicKey)
        let key = try MLDSA87.PublicKey(rawRepresentation: publicKey)
        return key.isValidSignature(signature, for: signedBytes, context: context)
    }
}
#endif
