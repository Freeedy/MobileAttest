namespace MobileAttest.Protocol;

/// <summary>
/// The algorithm a device signature is checked under.
/// </summary>
/// <remarks>
/// <para>
/// The value is chosen by the caller and defaulted by the library. It is never read from
/// the signature, the key, or anything else that arrives with a request: a verifier that
/// takes its algorithm from attacker-influenced input can be talked into a weaker check,
/// and the way to close that is to have nowhere for such a value to enter.
/// </para>
/// <para>
/// Zero is left unnamed on purpose, so <c>default(DeviceSignatureAlgorithm)</c> is not a
/// working algorithm. A field that was never populated is refused rather than quietly
/// treated as the default.
/// </para>
/// </remarks>
public enum DeviceSignatureAlgorithm
{
    /// <summary>
    /// ECDSA over SHA-256 -- the default, and today the only value.
    /// </summary>
    /// <remarks>
    /// It matches the material rather than merely being permitted by it. Apple offers no
    /// alternative for App Attest assertions, Android Keystore produces this from
    /// <c>SHA256withECDSA</c>, and the device certificates on both platforms are themselves
    /// signed <c>ecdsa-with-SHA256</c>. ECDSA also truncates the digest to the bit length of
    /// the group order -- 256 for P-256 -- so a longer hash would be cut back to the same
    /// 256 bits and buy nothing.
    /// </remarks>
    EcdsaSha256 = 1,
}
