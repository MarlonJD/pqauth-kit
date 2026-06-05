import CryptoKit
import Foundation
import XCTest
@testable import PQAuthKitSwift

final class PQAuthVectorFixtureTests: XCTestCase {
    func testSharedFixtureContainsRequiredPositiveAndNegativeCases() throws {
        let fixture = try loadFixture()
        let positiveCases = try XCTUnwrap(fixture["positiveCases"] as? [[String: Any]])
        let negativeCases = try XCTUnwrap(fixture["negativeCases"] as? [[String: Any]])

        XCTAssertEqual(
            Set(positiveCases.compactMap { $0["trustStateObject"] as? String }),
            Set(PQAuthTrustStateObject.allCases.map(\.rawValue))
        )
        XCTAssertEqual(negativeCases.count, 9)
        XCTAssertEqual(fixture["fixtureKind"] as? String, "structural-non-cryptographic")

        let defaultHotPath = try XCTUnwrap(fixture["defaultMessageHotPath"] as? [String: Any])
        XCTAssertEqual(defaultHotPath["perMessagePQSignaturesEnabled"] as? Bool, false)
    }

    func testSharedFixtureMatchesDomainSeparatorsAndHashes() throws {
        let fixture = try loadFixture()
        let positiveCases = try XCTUnwrap(fixture["positiveCases"] as? [[String: Any]])
        let byId = Dictionary(uniqueKeysWithValues: positiveCases.compactMap { entry -> (String, [String: Any])? in
            guard let id = entry["id"] as? String else { return nil }
            return (id, entry)
        })

        for trustStateObject in PQAuthTrustStateObject.allCases {
            let entry = try XCTUnwrap(byId[trustStateObject.rawValue])
            XCTAssertEqual(entry["signedBytesDomain"] as? String, trustStateObject.domainSeparator)

            let canonicalBytes = try XCTUnwrap(entry["canonicalBytesUtf8"] as? String)
            let hash = SHA256.hash(data: Data(canonicalBytes.utf8))
            XCTAssertEqual(Data(hash).base64URLEncodedString(), entry["signedBytesHash"] as? String)

            let signature = try XCTUnwrap(entry["hybridSignature"] as? [String: Any])
            let mldsa = try XCTUnwrap(signature["mldsa"] as? [String: Any])
            XCTAssertEqual(mldsa["algorithm"] as? String, PQAuthParameterSet.mldsa65.rawValue)
        }
    }

    func testSharedFixtureUsesFIPS204Lengths() throws {
        let fixture = try loadFixture()
        let algorithms = try XCTUnwrap(fixture["algorithms"] as? [String: Any])
        let mldsa = try XCTUnwrap(algorithms["mldsa"] as? [String: Any])

        XCTAssertEqual(mldsa["privateKeyLength"] as? Int, PQAuthParameterSet.mldsa65.privateKeyLength)
        XCTAssertEqual(mldsa["publicKeyLength"] as? Int, PQAuthParameterSet.mldsa65.publicKeyLength)
        XCTAssertEqual(mldsa["signatureLength"] as? Int, PQAuthParameterSet.mldsa65.signatureLength)
    }

    func testMLDSAConformanceFixtureIsProviderGeneratedCryptographicEvidence() throws {
        let fixture = try loadConformanceFixture()
        XCTAssertEqual(fixture["schema"] as? String, "pqauth-kit-mldsa-conformance-v1")
        XCTAssertEqual(fixture["fixtureKind"] as? String, "cryptographic-provider-conformance")

        let operations = try XCTUnwrap(fixture["operations"] as? [String])
        XCTAssertTrue(operations.contains("keygen"))
        XCTAssertTrue(operations.contains("sign"))
        XCTAssertTrue(operations.contains("verify"))
        XCTAssertTrue(operations.contains("public-key-import"))
        XCTAssertTrue(operations.contains("private-key-import"))

        if #available(iOS 26.0, macOS 26.0, *) {
            let cases = try XCTUnwrap(fixture["cases"] as? [[String: Any]])
            let entry = try XCTUnwrap(cases.first)
            XCTAssertEqual(entry["trustStateObject"] as? String, PQAuthTrustStateObject.deviceIdentity.rawValue)
            XCTAssertEqual(entry["signedBytesDomain"] as? String, PQAuthTrustStateObject.deviceIdentity.domainSeparator)

            let canonicalBytes = Data(try XCTUnwrap(entry["canonicalBytesUtf8"] as? String).utf8)
            let context = try Data(base64URL: XCTUnwrap(entry["context"] as? String))
            let publicKeyFixture = try XCTUnwrap(entry["publicKey"] as? [String: Any])
            let privateKeyFixture = try XCTUnwrap(entry["privateKey"] as? [String: Any])
            let signatureFixture = try XCTUnwrap(entry["signature"] as? [String: Any])
            let publicKeyData = try Data(base64URL: XCTUnwrap(publicKeyFixture["value"] as? String))
            let privateKeyData = try Data(base64URL: XCTUnwrap(privateKeyFixture["value"] as? String))
            let signature = try Data(base64URL: XCTUnwrap(signatureFixture["value"] as? String))

            XCTAssertEqual(publicKeyData.count, PQAuthParameterSet.mldsa65.publicKeyLength)
            XCTAssertEqual(signature.count, PQAuthParameterSet.mldsa65.signatureLength)

            let publicKey = try MLDSA65.PublicKey(rawRepresentation: publicKeyData)
            XCTAssertTrue(publicKey.isValidSignature(signature, for: canonicalBytes, context: context))
            XCTAssertFalse(publicKey.isValidSignature(signature, for: Data("wrong canonical bytes".utf8), context: context))
            XCTAssertFalse(publicKey.isValidSignature(signature, for: canonicalBytes, context: Data("wrong context".utf8)))
            XCTAssertThrowsError(try MLDSA65.PublicKey(rawRepresentation: publicKeyData.dropLast()))

            let privateKey = try MLDSA65.PrivateKey(integrityCheckedRepresentation: privateKeyData)
            let regeneratedSignature = try privateKey.signature(for: canonicalBytes, context: context)
            XCTAssertTrue(privateKey.publicKey.isValidSignature(regeneratedSignature, for: canonicalBytes, context: context))
        }
    }

    func testCryptoKitMLDSA65ProviderSignsAndVerifiesEveryTrustStateObject() throws {
        guard #available(iOS 26.0, macOS 26.0, *) else {
            throw XCTSkip("CryptoKit MLDSA65 provider-backed evidence requires OS 26.0 or newer.")
        }

        let fixture = try loadFixture()
        let positiveCases = try XCTUnwrap(fixture["positiveCases"] as? [[String: Any]])
        let provider = CryptoKitMLDSA65Provider(platform: .macOS)
        let requiredTrustStateObjects: Set<String> = [
            "account_identity",
            "device_identity",
            "roster_publish",
            "prekey_bundle",
            "safety_number",
        ]
        var signedObjects = Set<String>()

        XCTAssertEqual(requiredTrustStateObjects, Set(PQAuthTrustStateObject.allCases.map(\.rawValue)))

        for entry in positiveCases {
            let trustStateObject = try XCTUnwrap(entry["trustStateObject"] as? String)
            let canonicalBytes = Data(try XCTUnwrap(entry["canonicalBytesUtf8"] as? String).utf8)
            let context = Data(try XCTUnwrap(entry["signedBytesDomain"] as? String).utf8)
            let keyPair = try provider.generateKeyPair()
            let privateKey = try XCTUnwrap(keyPair.privateKey)
            let signature = try provider.sign(canonicalBytes, context: context, privateKey: privateKey)

            XCTAssertEqual(keyPair.publicKey.count, PQAuthParameterSet.mldsa65.publicKeyLength)
            XCTAssertFalse(privateKey.isEmpty)
            XCTAssertEqual(signature.count, PQAuthParameterSet.mldsa65.signatureLength)
            XCTAssertTrue(try provider.verify(signature: signature, signedBytes: canonicalBytes, context: context, publicKey: keyPair.publicKey))
            XCTAssertFalse(try provider.verify(signature: signature, signedBytes: Data("wrong canonical bytes".utf8), context: context, publicKey: keyPair.publicKey))
            XCTAssertFalse(try provider.verify(signature: signature, signedBytes: canonicalBytes, context: Data("wrong context".utf8), publicKey: keyPair.publicKey))

            signedObjects.insert(trustStateObject)
        }

        XCTAssertEqual(signedObjects, requiredTrustStateObjects)
    }

    func testReadinessEvidenceManifestLinksBenchmarkAndSideChannelEvidence() throws {
        let readiness = try loadEvidenceFixture("readiness-gates-v1.json")
        XCTAssertEqual(readiness["schema"] as? String, "pqauth-kit-readiness-gates-v1")

        let providers = try XCTUnwrap(readiness["providers"] as? [[String: Any]])
        let cryptoKit = try XCTUnwrap(providers.first { provider in
            provider["providerId"] as? String == "apple.cryptokit.mldsa65.macos"
        })
        XCTAssertEqual(
            cryptoKit["conformanceVectorId"] as? String,
            "apple-cryptokit-mldsa65-macos-trust-state-profile-2026-06-05"
        )
        XCTAssertEqual(
            cryptoKit["benchmarkReportId"] as? String,
            "apple-cryptokit-mldsa65-macos-local-benchmark-2026-06-04"
        )
        XCTAssertEqual(
            cryptoKit["sideChannelReviewId"] as? String,
            "apple-cryptokit-mldsa65-macos-side-channel-review-2026-06-04"
        )
        XCTAssertEqual(cryptoKit["productionReady"] as? Bool, true)

        let cryptoKitIOS = try XCTUnwrap(providers.first { provider in
            provider["providerId"] as? String == "apple.cryptokit.mldsa65.ios"
        })
        XCTAssertEqual(
            cryptoKitIOS["conformanceVectorId"] as? String,
            "apple-cryptokit-mldsa65-ios-release-device-trust-state-profile-2026-06-05"
        )
        XCTAssertEqual(
            cryptoKitIOS["benchmarkReportId"] as? String,
            "apple-cryptokit-mldsa65-ios-release-device-benchmark-2026-06-05"
        )
        XCTAssertEqual(
            cryptoKitIOS["sideChannelReviewId"] as? String,
            "apple-cryptokit-mldsa65-ios-side-channel-review-2026-06-05"
        )
        XCTAssertEqual(cryptoKitIOS["productionReady"] as? Bool, true)

        let benchmark = try loadEvidenceFixture("apple-cryptokit-mldsa65-macos-benchmark-2026-06-04.json")
        XCTAssertEqual(benchmark["schema"] as? String, "pqauth-kit-benchmark-evidence-v1")
        let operations = try XCTUnwrap(benchmark["operations"] as? [String: Any])
        XCTAssertNotNil(operations["keygen"])
        XCTAssertNotNil(operations["sign"])
        XCTAssertNotNil(operations["verify"])
        XCTAssertNotNil(operations["malformedPublicKeyRejection"])
        XCTAssertNotNil(operations["malformedSignatureRejection"])
    }

    private func loadFixture() throws -> [String: Any] {
        let url = packageRootURL()
            .appendingPathComponent("vectors/hybrid-trust-state-v1.json")
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func loadConformanceFixture() throws -> [String: Any] {
        let url = packageRootURL()
            .appendingPathComponent("vectors/mldsa-conformance-v1.json")
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func loadEvidenceFixture(_ name: String) throws -> [String: Any] {
        let url = packageRootURL()
            .appendingPathComponent("docs/evidence")
            .appendingPathComponent(name)
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func packageRootURL() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .standardizedFileURL
    }
}

private extension Data {
    init(base64URL value: String) throws {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        base64.append(String(repeating: "=", count: padding))

        guard let data = Data(base64Encoded: base64) else {
            throw NSError(domain: "PQAuthVectorFixtureTests", code: 1)
        }

        self = data
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
