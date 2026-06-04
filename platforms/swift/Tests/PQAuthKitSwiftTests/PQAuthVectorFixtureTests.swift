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

    private func loadFixture() throws -> [String: Any] {
        let url = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("../../vectors/hybrid-trust-state-v1.json")
            .standardizedFileURL
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
