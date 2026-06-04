using System.Text;

namespace PQAuthKit;

public enum PQAuthTrustStateObject
{
    AccountIdentity,
    DeviceIdentity,
    RosterPublish,
    PrekeyBundle,
    SafetyNumber
}

public static class PQAuthTrustStateDomains
{
    public static string DomainSeparator(this PQAuthTrustStateObject trustStateObject) =>
        trustStateObject switch
        {
            PQAuthTrustStateObject.AccountIdentity => "pqauth-kit-account-identity-hybrid-auth-v1",
            PQAuthTrustStateObject.DeviceIdentity => "pqauth-kit-device-identity-hybrid-auth-v1",
            PQAuthTrustStateObject.RosterPublish => "pqauth-kit-device-roster-hybrid-auth-v1",
            PQAuthTrustStateObject.PrekeyBundle => "pqauth-kit-ratchet-prekey-bundle-hybrid-auth-v1",
            PQAuthTrustStateObject.SafetyNumber => "pqauth-kit-safety-number-hybrid-auth-v1",
            _ => throw new ArgumentOutOfRangeException(nameof(trustStateObject), trustStateObject, "Unsupported trust-state object")
        };

    public static byte[] DomainContext(this PQAuthTrustStateObject trustStateObject) =>
        Encoding.UTF8.GetBytes(trustStateObject.DomainSeparator());
}

public static class PQAuthDeterministicTestEntropy
{
    public static byte[] Bytes(int count, bool production)
    {
        if (production)
        {
            throw new InvalidOperationException("deterministic entropy is unavailable to production APIs");
        }

        var bytes = new byte[count];
        for (var index = 0; index < bytes.Length; index += 1)
        {
            bytes[index] = (byte)(index % 251);
        }

        return bytes;
    }
}
