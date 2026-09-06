namespace MobileAttest.Abstractions;

/// <summary>
/// The mobile platform whose attestation mechanism produced a request.
/// </summary>
/// <remarks>
/// There is deliberately no zero member. An attestation result must always name the
/// platform that produced it, so a default-initialised value is invalid by construction
/// rather than silently reading as a real platform.
/// </remarks>
public enum Platform
{
    /// <summary>Android Key Attestation: an X.509 chain carrying a KeyDescription extension.</summary>
    Android = 1,

    /// <summary>Apple App Attest: a CBOR attestation object carrying an x5c chain.</summary>
    Apple = 2,
}
