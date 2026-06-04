import XCTest
@testable import PQAuthKitSwift

final class PQAuthMacOSPolicyTests: XCTestCase {
    func testMacOS26SelectsCryptoKitWhenAvailable() throws {
        let selected = try PQAuthProviderCatalog.apple(platform: .macOS).selectProvider(
            policy: PQAuthProviderSelectionPolicy(platform: .macOS),
            runtime: PQAuthRuntimeCapabilities(
                osMajorVersion: 26,
                cryptoKitMLDSA65Available: true,
                cryptoKitMLDSA87Available: true,
                secureEnclaveMLDSA65Available: true,
                secureEnclaveMLDSA87Available: true,
                auditedSwiftFallbackAvailable: false,
                isAppleSiliconMac: true
            )
        )

        XCTAssertEqual(selected.providerId, "apple.cryptokit.mldsa65.macos")
        XCTAssertEqual(selected.minimumOSOrRuntime, "macOS 26.0")
    }

    func testMacOSSecureEnclaveRequiresAppleSiliconAndLifecycleCompatibility() throws {
        let catalog = PQAuthProviderCatalog.apple(platform: .macOS)
        let policy = PQAuthProviderSelectionPolicy(
            platform: .macOS,
            preferHardwareIsolation: true,
            lifecycleAllowsNonExportableKeys: true
        )

        let intelSelection = try catalog.selectProvider(
            policy: policy,
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
        XCTAssertFalse(intelSelection.isHardwareIsolated)

        let appleSiliconSelection = try catalog.selectProvider(
            policy: policy,
            runtime: PQAuthRuntimeCapabilities(
                osMajorVersion: 26,
                cryptoKitMLDSA65Available: true,
                cryptoKitMLDSA87Available: true,
                secureEnclaveMLDSA65Available: true,
                secureEnclaveMLDSA87Available: true,
                auditedSwiftFallbackAvailable: false,
                isAppleSiliconMac: true
            )
        )
        XCTAssertTrue(appleSiliconSelection.isHardwareIsolated)
    }

    func testMacOSHybridAuthRequiredFailsClosedWhenProviderUnavailable() {
        XCTAssertThrowsError(try PQAuthProviderCatalog.apple(platform: .macOS).selectProvider(
            policy: PQAuthProviderSelectionPolicy(platform: .macOS),
            runtime: PQAuthRuntimeCapabilities(
                osMajorVersion: 25,
                cryptoKitMLDSA65Available: false,
                cryptoKitMLDSA87Available: false,
                secureEnclaveMLDSA65Available: false,
                secureEnclaveMLDSA87Available: false,
                auditedSwiftFallbackAvailable: false,
                isAppleSiliconMac: true
            )
        )) { error in
            XCTAssertEqual(error as? PQAuthError, .noApprovedProvider)
        }
    }
}
