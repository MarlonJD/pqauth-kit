import Foundation

public enum PQAuthTrustStateObject: String, CaseIterable, Codable, Equatable, Sendable {
    case accountIdentity = "account_identity"
    case deviceIdentity = "device_identity"
    case rosterPublish = "roster_publish"
    case prekeyBundle = "prekey_bundle"
    case safetyNumber = "safety_number"

    public var domainSeparator: String {
        switch self {
        case .accountIdentity:
            return "pqauth-kit-account-identity-hybrid-auth-v1"
        case .deviceIdentity:
            return "pqauth-kit-device-identity-hybrid-auth-v1"
        case .rosterPublish:
            return "pqauth-kit-device-roster-hybrid-auth-v1"
        case .prekeyBundle:
            return "pqauth-kit-ratchet-prekey-bundle-hybrid-auth-v1"
        case .safetyNumber:
            return "pqauth-kit-safety-number-hybrid-auth-v1"
        }
    }

    public var domainContext: Data {
        Data(domainSeparator.utf8)
    }
}

public enum PQAuthDeterministicTestEntropy {
    public static func bytes(count: Int, production: Bool) throws -> Data {
        guard !production else {
            throw PQAuthError.deterministicEntropyUnavailableInProduction
        }

        return Data((0..<count).map { UInt8($0 % 251) })
    }
}
