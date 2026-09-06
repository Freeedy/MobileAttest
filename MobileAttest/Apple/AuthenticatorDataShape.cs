namespace MobileAttest.Apple;

/// <summary>
/// Which App Attest message the authenticator data was taken from, and therefore which
/// layout it must satisfy.
/// </summary>
/// <remarks>
/// <para>
/// App Attest uses the same 37-byte prefix in two messages, but only one of them carries
/// attested credential data. The flags byte does not distinguish them: a real assertion
/// captured from a device sets the attested-credential-data bit (<c>0x40</c>) while
/// sending no credential data at all, so a parser that reads the flag as a promise about
/// the payload rejects genuine assertions.
/// </para>
/// <para>
/// The shape is therefore supplied by the caller, which knows which message it is holding,
/// and is never inferred from the bytes. Inferring it would let a sender choose its own
/// validation rules by trimming its input.
/// </para>
/// </remarks>
public enum AuthenticatorDataShape
{
    /// <summary>
    /// Authenticator data from an attestation object. Attested credential data -- the
    /// AAGUID, the credential identifier and the public key -- is required, and input
    /// without it is rejected.
    /// </summary>
    /// <remarks>
    /// This is the value a default-initialised field carries, so an uninitialised caller
    /// gets the strict layout rather than the permissive one.
    /// </remarks>
    Attestation = 0,

    /// <summary>
    /// Authenticator data from an assertion object. The structure is exactly the 37-byte
    /// prefix; anything longer or shorter is rejected, and no attested credential data is
    /// exposed regardless of the flags byte.
    /// </summary>
    Assertion = 1,
}
