namespace MobileAttest.Apple;

/// <summary>
/// Which digest an App Attest assertion signature is made over.
/// </summary>
/// <remarks>
/// <para>
/// The step Apple's procedure describes -- "verify that the signature is valid for the
/// nonce" -- has two readings, and they produce different bytes. Naming the one this library
/// checks makes the choice reviewable instead of leaving it implicit in a call somewhere.
/// </para>
/// <para>
/// It is named rather than numbered on purpose. A count of hashing rounds looks like a dial
/// to turn, a wrong setting fails silently, and nobody reading the call site afterwards can
/// say what the number meant.
/// </para>
/// <para>
/// One value exists, because one has been measured. A second will be added when a second
/// construction is observed on a real device, and not before: an option nobody has seen is a
/// guess with a public name on it.
/// </para>
/// </remarks>
public enum AppleAssertionDigest
{
    /// <summary>
    /// The nonce -- <c>SHA-256(authenticatorData ‖ clientDataHash)</c> -- handed to an
    /// ECDSA-with-SHA-256 signer as its <b>message</b>, so the value actually signed is
    /// <c>SHA-256(nonce)</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Measured on a real iOS App Attest capture, 2026-09-06, and confirmed independently on
    /// a second toolchain: the signature in that capture verifies under exactly this
    /// construction, and under the key Apple's credential certificate attests. Only the holder
    /// of the attested private key -- the Secure Enclave -- could have produced it, so this is
    /// what a device emits and not what a capture tool invented.
    /// </para>
    /// <para>
    /// The reading it rules out is treating the nonce as the final digest, which is the same
    /// as feeding <c>authenticatorData ‖ clientDataHash</c> straight to a SHA-256 signer. That
    /// form is refused, and a test pins the refusal.
    /// </para>
    /// <para>
    /// This is the default, so a caller that configures nothing gets the construction that was
    /// measured.
    /// </para>
    /// </remarks>
    NonceSignedAsMessage = 0,
}
