import Foundation

public struct PQAuthRuntimeCapabilities: Equatable, Sendable {
    public let osMajorVersion: Int
    public let cryptoKitMLDSA65Available: Bool
    public let cryptoKitMLDSA87Available: Bool
    public let secureEnclaveMLDSA65Available: Bool
    public let secureEnclaveMLDSA87Available: Bool
    public let auditedSwiftFallbackAvailable: Bool
    public let isAppleSiliconMac: Bool

    public init(
        osMajorVersion: Int,
        cryptoKitMLDSA65Available: Bool,
        cryptoKitMLDSA87Available: Bool,
        secureEnclaveMLDSA65Available: Bool,
        secureEnclaveMLDSA87Available: Bool,
        auditedSwiftFallbackAvailable: Bool,
        isAppleSiliconMac: Bool
    ) {
        self.osMajorVersion = osMajorVersion
        self.cryptoKitMLDSA65Available = cryptoKitMLDSA65Available
        self.cryptoKitMLDSA87Available = cryptoKitMLDSA87Available
        self.secureEnclaveMLDSA65Available = secureEnclaveMLDSA65Available
        self.secureEnclaveMLDSA87Available = secureEnclaveMLDSA87Available
        self.auditedSwiftFallbackAvailable = auditedSwiftFallbackAvailable
        self.isAppleSiliconMac = isAppleSiliconMac
    }

    public static func currentAppleRuntime(isAppleSiliconMac: Bool) -> Self {
        let majorVersion = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        let os26OrNewer = majorVersion >= 26
        return Self(
            osMajorVersion: majorVersion,
            cryptoKitMLDSA65Available: os26OrNewer,
            cryptoKitMLDSA87Available: os26OrNewer,
            secureEnclaveMLDSA65Available: os26OrNewer,
            secureEnclaveMLDSA87Available: os26OrNewer,
            auditedSwiftFallbackAvailable: false,
            isAppleSiliconMac: isAppleSiliconMac
        )
    }
}

public struct PQAuthProviderSelectionPolicy: Equatable, Sendable {
    public let platform: PQAuthPlatform
    public let requestedParameterSet: PQAuthParameterSet
    public let hybridAuthRequired: Bool
    public let preferHardwareIsolation: Bool
    public let lifecycleAllowsNonExportableKeys: Bool
    public let allowAuditedFallback: Bool
    public let isProduction: Bool

    public init(
        platform: PQAuthPlatform,
        requestedParameterSet: PQAuthParameterSet = .mldsa65,
        hybridAuthRequired: Bool = true,
        preferHardwareIsolation: Bool = false,
        lifecycleAllowsNonExportableKeys: Bool = false,
        allowAuditedFallback: Bool = false,
        isProduction: Bool = true
    ) {
        self.platform = platform
        self.requestedParameterSet = requestedParameterSet
        self.hybridAuthRequired = hybridAuthRequired
        self.preferHardwareIsolation = preferHardwareIsolation
        self.lifecycleAllowsNonExportableKeys = lifecycleAllowsNonExportableKeys
        self.allowAuditedFallback = allowAuditedFallback
        self.isProduction = isProduction
    }
}

public struct PQAuthProviderCatalog: Sendable {
    public let providers: [PQAuthProviderMetadata]

    public init(providers: [PQAuthProviderMetadata]) {
        self.providers = providers
    }

    public static func apple(platform: PQAuthPlatform) -> Self {
        let osName = platform.rawValue
        let cryptoKitMLDSA65Evidence = PQAuthEvidenceReferences.appleCryptoKitDocs(
            providerVersion: "\(osName) 26.0 SDK documentation",
            conformanceVectorId: platform == .macOS ? "apple-cryptokit-mldsa65-device-identity-2026-06-04" : nil,
            benchmarkReportId: platform == .macOS ? "apple-cryptokit-mldsa65-macos-local-benchmark-2026-06-04" : nil,
            sideChannelReviewId: platform == .macOS ? "apple-cryptokit-mldsa65-macos-side-channel-review-2026-06-04" : nil,
            remainingRisk: "Additional provider conformance, release-device benchmark, and side-channel evidence remain pending."
        )
        let cryptoKitMLDSA87Evidence = PQAuthEvidenceReferences.appleCryptoKitDocs(
            providerVersion: "\(osName) 26.0 SDK documentation",
            remainingRisk: "Provider conformance, release-device benchmark, and side-channel evidence remain pending."
        )
        let secureEnclaveEvidence = PQAuthEvidenceReferences.appleSecureEnclaveDocs(
            providerVersion: "\(osName) 26.0 SDK documentation",
            remainingRisk: "Provider conformance, lifecycle approval, release-device benchmark, and side-channel evidence remain pending."
        )
        return Self(providers: [
            PQAuthProviderMetadata(
                providerId: "apple.cryptokit.mldsa65.\(osName.lowercased())",
                parameterSet: .mldsa65,
                isPlatformNative: true,
                isHardwareIsolated: false,
                minimumOSOrRuntime: "\(osName) 26.0",
                supportsKeyGeneration: true,
                supportsSign: true,
                supportsVerify: true,
                privateKeyExportPolicy: .exportable,
                usesCOrFFI: false,
                nativeLibraryDependency: false,
                fallbackAllowedInProduction: false,
                auditStatus: .approved,
                benchmarkStatus: .pending,
                sideChannelReviewStatus: .pending,
                evidence: cryptoKitMLDSA65Evidence
            ),
            PQAuthProviderMetadata(
                providerId: "apple.cryptokit.mldsa87.\(osName.lowercased())",
                parameterSet: .mldsa87,
                isPlatformNative: true,
                isHardwareIsolated: false,
                minimumOSOrRuntime: "\(osName) 26.0",
                supportsKeyGeneration: true,
                supportsSign: true,
                supportsVerify: true,
                privateKeyExportPolicy: .exportable,
                usesCOrFFI: false,
                nativeLibraryDependency: false,
                fallbackAllowedInProduction: false,
                auditStatus: .approved,
                benchmarkStatus: .pending,
                sideChannelReviewStatus: .pending,
                evidence: cryptoKitMLDSA87Evidence
            ),
            PQAuthProviderMetadata(
                providerId: "apple.secure-enclave.mldsa65.\(osName.lowercased())",
                parameterSet: .mldsa65,
                isPlatformNative: true,
                isHardwareIsolated: true,
                minimumOSOrRuntime: "\(osName) 26.0",
                supportsKeyGeneration: true,
                supportsSign: true,
                supportsVerify: false,
                privateKeyExportPolicy: .nonExportableHardware,
                usesCOrFFI: false,
                nativeLibraryDependency: false,
                fallbackAllowedInProduction: false,
                auditStatus: .approved,
                benchmarkStatus: .pending,
                sideChannelReviewStatus: .pending,
                evidence: secureEnclaveEvidence
            ),
            PQAuthProviderMetadata(
                providerId: "apple.secure-enclave.mldsa87.\(osName.lowercased())",
                parameterSet: .mldsa87,
                isPlatformNative: true,
                isHardwareIsolated: true,
                minimumOSOrRuntime: "\(osName) 26.0",
                supportsKeyGeneration: true,
                supportsSign: true,
                supportsVerify: false,
                privateKeyExportPolicy: .nonExportableHardware,
                usesCOrFFI: false,
                nativeLibraryDependency: false,
                fallbackAllowedInProduction: false,
                auditStatus: .approved,
                benchmarkStatus: .pending,
                sideChannelReviewStatus: .pending,
                evidence: secureEnclaveEvidence
            ),
            PQAuthProviderMetadata.swiftFallback(
                providerId: "swift.fallback.mldsa65.\(osName.lowercased())",
                parameterSet: .mldsa65,
                productionApproved: false
            )
        ])
    }

    public func selectProvider(
        policy: PQAuthProviderSelectionPolicy,
        runtime: PQAuthRuntimeCapabilities
    ) throws -> PQAuthProviderMetadata {
        let matchingProviders = providers.filter { $0.parameterSet == policy.requestedParameterSet }

        if policy.preferHardwareIsolation && policy.lifecycleAllowsNonExportableKeys {
            if let hardwareProvider = matchingProviders.first(where: { provider in
                provider.isHardwareIsolated && isProviderAvailable(provider, policy: policy, runtime: runtime)
            }) {
                return hardwareProvider
            }
        }

        if let nativeProvider = matchingProviders.first(where: { provider in
            provider.isPlatformNative && !provider.isHardwareIsolated && isProviderAvailable(provider, policy: policy, runtime: runtime)
        }) {
            return nativeProvider
        }

        if policy.allowAuditedFallback && runtime.auditedSwiftFallbackAvailable {
            if let fallbackProvider = matchingProviders.first(where: { provider in
                !provider.isPlatformNative && fallbackPermitted(provider, policy: policy)
            }) {
                return fallbackProvider
            }
        }

        if policy.hybridAuthRequired {
            throw PQAuthError.noApprovedProvider
        }

        throw PQAuthError.noApprovedProvider
    }

    private func isProviderAvailable(
        _ provider: PQAuthProviderMetadata,
        policy: PQAuthProviderSelectionPolicy,
        runtime: PQAuthRuntimeCapabilities
    ) -> Bool {
        guard runtime.osMajorVersion >= 26 else {
            return false
        }

        if policy.platform == .macOS && provider.isHardwareIsolated && !runtime.isAppleSiliconMac {
            return false
        }

        switch (provider.parameterSet, provider.isHardwareIsolated) {
        case (.mldsa65, false):
            return runtime.cryptoKitMLDSA65Available
        case (.mldsa87, false):
            return runtime.cryptoKitMLDSA87Available
        case (.mldsa65, true):
            return runtime.secureEnclaveMLDSA65Available
        case (.mldsa87, true):
            return runtime.secureEnclaveMLDSA87Available
        case (.mldsa44, _):
            return false
        }
    }

    private func fallbackPermitted(
        _ provider: PQAuthProviderMetadata,
        policy: PQAuthProviderSelectionPolicy
    ) -> Bool {
        guard !provider.isPlatformNative && !provider.usesCOrFFI && !provider.nativeLibraryDependency else {
            return false
        }

        return policy.isProduction
            ? provider.fallbackAllowedInProduction && provider.isProductionReady
            : provider.isProductionReady
    }
}

public extension PQAuthProviderMetadata {
    static func swiftFallback(
        providerId: String,
        parameterSet: PQAuthParameterSet,
        productionApproved: Bool,
        evidence: PQAuthEvidenceReferences = .none
    ) -> Self {
        Self(
            providerId: providerId,
            parameterSet: parameterSet,
            isPlatformNative: false,
            isHardwareIsolated: false,
            minimumOSOrRuntime: "Swift fallback",
            supportsKeyGeneration: productionApproved,
            supportsSign: productionApproved,
            supportsVerify: productionApproved,
            privateKeyExportPolicy: .exportable,
            usesCOrFFI: false,
            nativeLibraryDependency: false,
            fallbackAllowedInProduction: productionApproved,
            auditStatus: productionApproved ? .approved : .pending,
            benchmarkStatus: productionApproved ? .approved : .pending,
            sideChannelReviewStatus: productionApproved ? .approved : .pending,
            evidence: evidence
        )
    }
}

public extension PQAuthEvidenceReferences {
    static func complete(
        providerSourceId: String,
        providerVersion: String,
        providerCommit: String? = nil,
        license: String,
        conformanceVectorId: String,
        auditReportId: String,
        benchmarkReportId: String,
        sideChannelReviewId: String,
        remainingRisk: String? = nil
    ) -> Self {
        Self(
            providerSourceId: providerSourceId,
            providerVersion: providerVersion,
            providerCommit: providerCommit,
            license: license,
            conformanceVectorId: conformanceVectorId,
            auditReportId: auditReportId,
            benchmarkReportId: benchmarkReportId,
            sideChannelReviewId: sideChannelReviewId,
            remainingRisk: remainingRisk
        )
    }

    static func appleCryptoKitDocs(
        providerVersion: String,
        conformanceVectorId: String? = nil,
        benchmarkReportId: String? = nil,
        sideChannelReviewId: String? = nil,
        remainingRisk: String
    ) -> Self {
        Self(
            providerSourceId: "apple-cryptokit-mldsa-docs-2026-06-04",
            providerVersion: providerVersion,
            license: "Apple Developer Documentation",
            conformanceVectorId: conformanceVectorId,
            auditReportId: "apple-platform-provider-doc-review-2026-06-04",
            benchmarkReportId: benchmarkReportId,
            sideChannelReviewId: sideChannelReviewId,
            remainingRisk: remainingRisk
        )
    }

    static func appleSecureEnclaveDocs(providerVersion: String, remainingRisk: String) -> Self {
        Self(
            providerSourceId: "apple-secure-enclave-mldsa-docs-2026-06-04",
            providerVersion: providerVersion,
            license: "Apple Developer Documentation",
            auditReportId: "apple-secure-enclave-provider-doc-review-2026-06-04",
            remainingRisk: remainingRisk
        )
    }
}
