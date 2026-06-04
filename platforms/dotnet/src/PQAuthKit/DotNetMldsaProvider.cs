using System.Security.Cryptography;

namespace PQAuthKit;

public sealed class DotNetMldsaProvider(PQAuthParameterSet parameterSet)
{
    public PQAuthProviderMetadata Metadata { get; } = WindowsProviderCatalog.DotNetSystemProvider();

    public bool IsRuntimeSupported => MLDsa.IsSupported;

    public MLDsa GenerateKey()
    {
        if (!MLDsa.IsSupported)
        {
            throw new PlatformNotSupportedException("ML-DSA is not supported by this .NET runtime");
        }

        return MLDsa.GenerateKey(PQAuthParameterSetMetadata.For(parameterSet).ToDotNetAlgorithm());
    }

    public byte[] SignData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context, ReadOnlySpan<byte> privateKey)
    {
        if (!MLDsa.IsSupported)
        {
            throw new PlatformNotSupportedException("ML-DSA is not supported by this .NET runtime");
        }

        using var key = MLDsa.ImportMLDsaPrivateKey(
            PQAuthParameterSetMetadata.For(parameterSet).ToDotNetAlgorithm(),
            privateKey);
        var signature = new byte[PQAuthParameterSetMetadata.For(parameterSet).SignatureLength];
        key.SignData(data, signature, context);
        return signature;
    }

    public bool VerifyData(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> context,
        ReadOnlySpan<byte> publicKey)
    {
        var metadata = PQAuthParameterSetMetadata.For(parameterSet);
        if (publicKey.Length != metadata.PublicKeyLength)
        {
            throw new ArgumentException("Unexpected public key length", nameof(publicKey));
        }

        if (signature.Length != metadata.SignatureLength)
        {
            throw new ArgumentException("Unexpected signature length", nameof(signature));
        }

        if (!MLDsa.IsSupported)
        {
            throw new PlatformNotSupportedException("ML-DSA is not supported by this .NET runtime");
        }

        using var key = MLDsa.ImportMLDsaPublicKey(metadata.ToDotNetAlgorithm(), publicKey);
        return key.VerifyData(data, signature, context);
    }
}
