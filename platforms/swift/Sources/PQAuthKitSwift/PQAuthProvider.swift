import Foundation

public enum PQAuthAlgorithm: String, Codable, Equatable, Sendable {
    case mldsa = "ML-DSA"
}

public enum PQAuthParameterSet: String, Codable, CaseIterable, Equatable, Sendable {
    case mldsa44 = "ML-DSA-44"
    case mldsa65 = "ML-DSA-65"
    case mldsa87 = "ML-DSA-87"

    public var privateKeyLength: Int {
        switch self {
        case .mldsa44: return 2_560
        case .mldsa65: return 4_032
        case .mldsa87: return 4_896
        }
    }

    public var publicKeyLength: Int {
        switch self {
        case .mldsa44: return 1_312
        case .mldsa65: return 1_952
        case .mldsa87: return 2_592
        }
    }

    public var signatureLength: Int {
        switch self {
        case .mldsa44: return 2_420
        case .mldsa65: return 3_309
        case .mldsa87: return 4_627
        }
    }
}

public enum PQAuthPlatform: String, Codable, Equatable, Sendable {
    case iOS
    case macOS
}

public enum PQAuthPrivateKeyExportPolicy: String, Codable, Equatable, Sendable {
    case exportable
    case nonExportableHardware
    case prohibited
}

public enum PQAuthGateStatus: String, Codable, Equatable, Sendable {
    case pending
    case approved
    case rejected
}

public struct PQAuthProviderMetadata: Codable, Equatable, Sendable {
    public let providerId: String
    public let algorithm: PQAuthAlgorithm
    public let parameterSet: PQAuthParameterSet
    public let isPlatformNative: Bool
    public let isHardwareIsolated: Bool
    public let minimumOSOrRuntime: String
    public let supportsKeyGeneration: Bool
    public let supportsSign: Bool
    public let supportsVerify: Bool
    public let privateKeyExportPolicy: PQAuthPrivateKeyExportPolicy
    public let usesCOrFFI: Bool
    public let nativeLibraryDependency: Bool
    public let fallbackAllowedInProduction: Bool
    public let auditStatus: PQAuthGateStatus
    public let benchmarkStatus: PQAuthGateStatus
    public let sideChannelReviewStatus: PQAuthGateStatus

    public init(
        providerId: String,
        algorithm: PQAuthAlgorithm = .mldsa,
        parameterSet: PQAuthParameterSet,
        isPlatformNative: Bool,
        isHardwareIsolated: Bool,
        minimumOSOrRuntime: String,
        supportsKeyGeneration: Bool,
        supportsSign: Bool,
        supportsVerify: Bool,
        privateKeyExportPolicy: PQAuthPrivateKeyExportPolicy,
        usesCOrFFI: Bool,
        nativeLibraryDependency: Bool,
        fallbackAllowedInProduction: Bool,
        auditStatus: PQAuthGateStatus,
        benchmarkStatus: PQAuthGateStatus,
        sideChannelReviewStatus: PQAuthGateStatus
    ) {
        self.providerId = providerId
        self.algorithm = algorithm
        self.parameterSet = parameterSet
        self.isPlatformNative = isPlatformNative
        self.isHardwareIsolated = isHardwareIsolated
        self.minimumOSOrRuntime = minimumOSOrRuntime
        self.supportsKeyGeneration = supportsKeyGeneration
        self.supportsSign = supportsSign
        self.supportsVerify = supportsVerify
        self.privateKeyExportPolicy = privateKeyExportPolicy
        self.usesCOrFFI = usesCOrFFI
        self.nativeLibraryDependency = nativeLibraryDependency
        self.fallbackAllowedInProduction = fallbackAllowedInProduction
        self.auditStatus = auditStatus
        self.benchmarkStatus = benchmarkStatus
        self.sideChannelReviewStatus = sideChannelReviewStatus
    }

    public var hasApprovedProductionGates: Bool {
        auditStatus == .approved && benchmarkStatus == .approved && sideChannelReviewStatus == .approved
    }
}

public struct PQAuthKeyPair: Equatable, Sendable {
    public let publicKey: Data
    public let privateKey: Data?

    public init(publicKey: Data, privateKey: Data?) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

public enum PQAuthError: Error, Equatable {
    case noApprovedProvider
    case deterministicEntropyUnavailableInProduction
    case malformedPublicKey(expected: Int, actual: Int)
    case malformedSignature(expected: Int, actual: Int)
    case privateKeyExportBlocked
    case providerUnavailable(String)
    case unsupportedParameterSet(PQAuthParameterSet)
}

public protocol PQAuthProvider: Sendable {
    var metadata: PQAuthProviderMetadata { get }

    func generateKeyPair() throws -> PQAuthKeyPair
    func sign(_ signedBytes: Data, context: Data, privateKey: Data) throws -> Data
    func verify(signature: Data, signedBytes: Data, context: Data, publicKey: Data) throws -> Bool
}

public extension PQAuthProvider {
    func generateKeyPair() throws -> PQAuthKeyPair {
        throw PQAuthError.providerUnavailable(metadata.providerId)
    }

    func sign(_ signedBytes: Data, context: Data, privateKey: Data) throws -> Data {
        throw PQAuthError.providerUnavailable(metadata.providerId)
    }

    func verify(signature: Data, signedBytes: Data, context: Data, publicKey: Data) throws -> Bool {
        try validate(signature: signature, publicKey: publicKey)
        throw PQAuthError.providerUnavailable(metadata.providerId)
    }

    func validate(signature: Data, publicKey: Data) throws {
        let expectedPublicKeyLength = metadata.parameterSet.publicKeyLength
        guard publicKey.count == expectedPublicKeyLength else {
            throw PQAuthError.malformedPublicKey(expected: expectedPublicKeyLength, actual: publicKey.count)
        }

        let expectedSignatureLength = metadata.parameterSet.signatureLength
        guard signature.count == expectedSignatureLength else {
            throw PQAuthError.malformedSignature(expected: expectedSignatureLength, actual: signature.count)
        }
    }
}
