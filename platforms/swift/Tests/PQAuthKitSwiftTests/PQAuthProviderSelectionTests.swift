import XCTest
@testable import PQAuthKitSwift

final class PQAuthProviderSelectionTests: XCTestCase {
    func testIOS26SelectsCryptoKitWhenAvailable() throws {
        let selected = try PQAuthProviderCatalog.apple(platform: .iOS).selectProvider(
            policy: PQAuthProviderSelectionPolicy(platform: .iOS),
            runtime: PQAuthRuntimeCapabilities(
                osMajorVersion: 26,
                cryptoKitMLDSA65Available: true,
                cryptoKitMLDSA87Available: true,
                secureEnclaveMLDSA65Available: true,
                secureEnclaveMLDSA87Available: true,
                auditedSwiftFallbackAvailable: false,
                isAppleSiliconMac: false
            )
        )

        XCTAssertEqual(selected.providerId, "apple.cryptokit.mldsa65.ios")
        XCTAssertTrue(selected.isPlatformNative)
        XCTAssertFalse(selected.usesCOrFFI)
    }

    func testSecureEnclaveRequiresLifecycleOptIn() throws {
        let runtime = PQAuthRuntimeCapabilities(
            osMajorVersion: 26,
            cryptoKitMLDSA65Available: true,
            cryptoKitMLDSA87Available: true,
            secureEnclaveMLDSA65Available: true,
            secureEnclaveMLDSA87Available: true,
            auditedSwiftFallbackAvailable: false,
            isAppleSiliconMac: false
        )
        let catalog = PQAuthProviderCatalog.apple(platform: .iOS)

        let defaultSelection = try catalog.selectProvider(
            policy: PQAuthProviderSelectionPolicy(platform: .iOS, preferHardwareIsolation: true),
            runtime: runtime
        )
        XCTAssertFalse(defaultSelection.isHardwareIsolated)

        let secureEnclaveSelection = try catalog.selectProvider(
            policy: PQAuthProviderSelectionPolicy(
                platform: .iOS,
                preferHardwareIsolation: true,
                lifecycleAllowsNonExportableKeys: true
            ),
            runtime: runtime
        )
        XCTAssertTrue(secureEnclaveSelection.isHardwareIsolated)
        XCTAssertEqual(secureEnclaveSelection.privateKeyExportPolicy, .nonExportableHardware)
    }

    func testOlderIOSFailsClosedWithoutAuditedFallback() {
        XCTAssertThrowsError(try PQAuthProviderCatalog.apple(platform: .iOS).selectProvider(
            policy: PQAuthProviderSelectionPolicy(platform: .iOS),
            runtime: PQAuthRuntimeCapabilities(
                osMajorVersion: 25,
                cryptoKitMLDSA65Available: false,
                cryptoKitMLDSA87Available: false,
                secureEnclaveMLDSA65Available: false,
                secureEnclaveMLDSA87Available: false,
                auditedSwiftFallbackAvailable: false,
                isAppleSiliconMac: false
            )
        )) { error in
            XCTAssertEqual(error as? PQAuthError, .noApprovedProvider)
        }
    }

    func testAuditedSwiftFallbackCanBeSelectedOnlyWhenGatesAreApproved() throws {
        let catalog = PQAuthProviderCatalog(providers: [
            .swiftFallback(
                providerId: "swift.fallback.mldsa65.ios.approved-test",
                parameterSet: .mldsa65,
                productionApproved: true
            )
        ])

        let selected = try catalog.selectProvider(
            policy: PQAuthProviderSelectionPolicy(
                platform: .iOS,
                allowAuditedFallback: true,
                isProduction: true
            ),
            runtime: PQAuthRuntimeCapabilities(
                osMajorVersion: 25,
                cryptoKitMLDSA65Available: false,
                cryptoKitMLDSA87Available: false,
                secureEnclaveMLDSA65Available: false,
                secureEnclaveMLDSA87Available: false,
                auditedSwiftFallbackAvailable: true,
                isAppleSiliconMac: false
            )
        )

        XCTAssertEqual(selected.providerId, "swift.fallback.mldsa65.ios.approved-test")
        XCTAssertTrue(selected.fallbackAllowedInProduction)
        XCTAssertTrue(selected.hasApprovedProductionGates)
    }

    func testDeterministicEntropyIsTestOnly() throws {
        XCTAssertEqual(try PQAuthDeterministicTestEntropy.bytes(count: 4, production: false), Data([0, 1, 2, 3]))
        XCTAssertThrowsError(try PQAuthDeterministicTestEntropy.bytes(count: 4, production: true)) { error in
            XCTAssertEqual(error as? PQAuthError, .deterministicEntropyUnavailableInProduction)
        }
    }
}
