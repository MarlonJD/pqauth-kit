import CryptoKit
import Darwin
import Foundation
import PQAuthKitSwift
import SwiftUI
import UIKit

@main
struct PQAuthKitIOSDeviceHarnessApp: App {
    @UIApplicationDelegateAdaptor(HarnessAppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            Text("PQAuthKit iOS Device Harness")
                .padding()
        }
    }
}

final class HarnessAppDelegate: NSObject, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        DispatchQueue.main.async {
            do {
                let evidence = try IOSDeviceEvidenceRunner().run()
                let data = try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
                let json = String(data: data, encoding: .utf8) ?? "{}"
                print("PQAUTH_IOS_DEVICE_EVIDENCE_JSON=\(json)")
                fflush(stdout)
                exit(0)
            } catch {
                print("PQAUTH_IOS_DEVICE_EVIDENCE_ERROR=\(error)")
                fflush(stdout)
                exit(2)
            }
        }
        return true
    }
}

private struct IOSDeviceEvidenceRunner {
    private let structuralVectorResourceName = "hybrid-trust-state-v1.json"
    private let readinessGateResourceName = "readiness-gates-v1.json"

    private let requiredTrustStateObjects: Set<String> = [
        "account_identity",
        "device_identity",
        "roster_publish",
        "prekey_bundle",
        "safety_number",
    ]

    func run() throws -> [String: Any] {
        guard #available(iOS 26.0, *) else {
            throw HarnessError.unsupportedRuntime(ProcessInfo.processInfo.operatingSystemVersionString)
        }

        let fixture = try loadJSONResource(fileName: structuralVectorResourceName)
        let positiveCases = try requireArray(fixture["positiveCases"], field: "positiveCases")
        let provider = CryptoKitMLDSA65Provider(platform: .iOS)
        var signedObjects = Set<String>()
        var timings = BenchmarkTimings()

        guard provider.metadata.providerId == "apple.cryptokit.mldsa65.ios" else {
            throw HarnessError.unexpectedValue("providerId", provider.metadata.providerId)
        }
        guard Set(PQAuthTrustStateObject.allCases.map(\.rawValue)) == requiredTrustStateObjects else {
            throw HarnessError.unexpectedValue("trustStateObjects", "\(PQAuthTrustStateObject.allCases)")
        }

        for entry in positiveCases {
            let trustStateObject = try requireString(entry["trustStateObject"], field: "trustStateObject")
            let canonicalBytes = Data(try requireString(entry["canonicalBytesUtf8"], field: "canonicalBytesUtf8").utf8)
            let context = Data(try requireString(entry["signedBytesDomain"], field: "signedBytesDomain").utf8)
            let keyPair = try timings.record("keygen") {
                try provider.generateKeyPair()
            }
            let privateKey = try requireData(keyPair.privateKey, field: "privateKey")
            let importedPublicKey = try timings.record("publicKeyImport") {
                try MLDSA65.PublicKey(rawRepresentation: keyPair.publicKey)
            }
            let importedPrivateKey = try timings.record("privateKeyImport") {
                try MLDSA65.PrivateKey(integrityCheckedRepresentation: privateKey)
            }
            let exportedPublicKey = timings.record("publicKeyExport") {
                importedPublicKey.rawRepresentation
            }
            let exportedPrivateKey = timings.record("privateKeyExport") {
                importedPrivateKey.integrityCheckedRepresentation
            }
            let signature = try timings.record("sign") {
                try provider.sign(canonicalBytes, context: context, privateKey: privateKey)
            }
            let verified = try timings.record("verify") {
                try provider.verify(
                    signature: signature,
                    signedBytes: canonicalBytes,
                    context: context,
                    publicKey: keyPair.publicKey
                )
            }

            try require(verified, "expected valid signature for \(trustStateObject)")
            try require(exportedPublicKey.count == PQAuthParameterSet.mldsa65.publicKeyLength, "unexpected public-key length")
            try require(!exportedPrivateKey.isEmpty, "private key export must be non-empty")
            try require(signature.count == PQAuthParameterSet.mldsa65.signatureLength, "unexpected signature length")

            let wrongBytesAccepted = try provider.verify(
                signature: signature,
                signedBytes: Data("wrong canonical bytes".utf8),
                context: context,
                publicKey: keyPair.publicKey
            )
            let wrongContextAccepted = try provider.verify(
                signature: signature,
                signedBytes: canonicalBytes,
                context: Data("wrong context".utf8),
                publicKey: keyPair.publicKey
            )
            try require(!wrongBytesAccepted, "wrong canonical bytes must be rejected")
            try require(!wrongContextAccepted, "wrong context must be rejected")

            try require(
                timings.recordRejection("malformedPublicKeyRejection") {
                    _ = try provider.verify(
                        signature: signature,
                        signedBytes: canonicalBytes,
                        context: context,
                        publicKey: Data(keyPair.publicKey.dropLast())
                    )
                },
                "malformed public key must throw"
            )
            try require(
                timings.recordRejection("malformedSignatureRejection") {
                    _ = try provider.verify(
                        signature: Data(signature.dropLast()),
                        signedBytes: canonicalBytes,
                        context: context,
                        publicKey: keyPair.publicKey
                    )
                },
                "malformed signature must throw"
            )

            signedObjects.insert(trustStateObject)
        }

        try require(signedObjects == requiredTrustStateObjects, "not all trust-state objects were covered")
        let readiness = try loadJSONResource(fileName: readinessGateResourceName)
        let iosReadiness = iosProviderReadiness(readiness)

        return [
            "schema": "pqauth-kit-ios-device-evidence-v1",
            "version": 1,
            "evidenceId": "apple-cryptokit-mldsa65-ios-release-device-trust-state-profile-2026-06-05",
            "benchmarkReportId": "apple-cryptokit-mldsa65-ios-release-device-benchmark-2026-06-05",
            "providerId": provider.metadata.providerId,
            "parameterSet": PQAuthParameterSet.mldsa65.rawValue,
            "device": [
                "name": UIDevice.current.name,
                "model": UIDevice.current.model,
                "systemName": UIDevice.current.systemName,
                "systemVersion": UIDevice.current.systemVersion,
            ],
            "providerBackedTrustStateObjects": Array(requiredTrustStateObjects).sorted(),
            "operations": timings.report(),
            "readinessManifestIOSProductionReady": iosReadiness?["productionReady"] as? Bool ?? false,
            "remainingRisk": "Package-boundary iOS release-device evidence; Apple provider internals remain under Apple's provider boundary.",
        ]
    }

    private func loadJSONResource(fileName: String) throws -> [String: Any] {
        let resourceName = (fileName as NSString).deletingPathExtension
        let resourceExtension = (fileName as NSString).pathExtension
        guard let url = Bundle.main.url(forResource: resourceName, withExtension: resourceExtension) else {
            throw HarnessError.missingResource(fileName)
        }
        let data = try Data(contentsOf: url)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw HarnessError.invalidJSON(fileName)
        }
        return json
    }

    private func iosProviderReadiness(_ readiness: [String: Any]) -> [String: Any]? {
        guard let providers = readiness["providers"] as? [[String: Any]] else {
            return nil
        }
        return providers.first { provider in
            provider["providerId"] as? String == "apple.cryptokit.mldsa65.ios"
        }
    }
}

private struct BenchmarkTimings {
    private var values: [String: [Double]] = [:]

    mutating func record<T>(_ operation: String, _ body: () throws -> T) rethrows -> T {
        let start = CFAbsoluteTimeGetCurrent()
        let result = try body()
        let elapsedMs = (CFAbsoluteTimeGetCurrent() - start) * 1_000
        values[operation, default: []].append(elapsedMs)
        return result
    }

    mutating func recordRejection(_ operation: String, _ body: () throws -> Void) -> Bool {
        let start = CFAbsoluteTimeGetCurrent()
        do {
            try body()
            let elapsedMs = (CFAbsoluteTimeGetCurrent() - start) * 1_000
            values[operation, default: []].append(elapsedMs)
            return false
        } catch {
            let elapsedMs = (CFAbsoluteTimeGetCurrent() - start) * 1_000
            values[operation, default: []].append(elapsedMs)
            return true
        }
    }

    func report() -> [String: Any] {
        values.mapValues { samples in
            let sorted = samples.sorted()
            return [
                "iterations": sorted.count,
                "minMs": sorted.first ?? 0,
                "p50Ms": percentile(sorted, 0.50),
                "p95Ms": percentile(sorted, 0.95),
                "maxMs": sorted.last ?? 0,
            ]
        }
    }

    private func percentile(_ sorted: [Double], _ percentile: Double) -> Double {
        guard !sorted.isEmpty else {
            return 0
        }
        let index = max(0, min(sorted.count - 1, Int((Double(sorted.count - 1) * percentile).rounded(.up))))
        return sorted[index]
    }
}

private func require(_ condition: Bool, _ message: String) throws {
    if !condition {
        throw HarnessError.assertion(message)
    }
}

private func requireArray(_ value: Any?, field: String) throws -> [[String: Any]] {
    guard let array = value as? [[String: Any]] else {
        throw HarnessError.missingField(field)
    }
    return array
}

private func requireString(_ value: Any?, field: String) throws -> String {
    guard let string = value as? String else {
        throw HarnessError.missingField(field)
    }
    return string
}

private func requireData(_ value: Data?, field: String) throws -> Data {
    guard let data = value else {
        throw HarnessError.missingField(field)
    }
    return data
}

private enum HarnessError: Error, CustomStringConvertible {
    case assertion(String)
    case invalidJSON(String)
    case missingField(String)
    case missingResource(String)
    case unexpectedValue(String, String)
    case unsupportedRuntime(String)

    var description: String {
        switch self {
        case .assertion(let message):
            return "assertion failed: \(message)"
        case .invalidJSON(let resource):
            return "invalid JSON resource: \(resource)"
        case .missingField(let field):
            return "missing field: \(field)"
        case .missingResource(let resource):
            return "missing resource: \(resource).json"
        case .unexpectedValue(let field, let value):
            return "unexpected \(field): \(value)"
        case .unsupportedRuntime(let runtime):
            return "unsupported runtime: \(runtime)"
        }
    }
}
