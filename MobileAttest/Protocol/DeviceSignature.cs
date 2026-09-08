using System;
using MobileAttest.Abstractions;
using MobileAttest.Apple;
using Org.BouncyCastle.Crypto.Parameters;

namespace MobileAttest.Protocol;

/// <summary>
/// Checks a signature made by an attested device key against the public key that
/// attestation returned.
/// </summary>
/// <remarks>
/// <para>
/// Attestation answers one question, once: was this key created in real hardware, by this
/// application, on this device. This type answers the other question, on every later
/// request: <b>did that same key sign these bytes.</b> Together they are the whole of what
/// a device key proves.
/// </para>
///
/// <para><b>The signed bytes are opaque here</b></para>
/// <para>
/// The signed bytes are passed to the verifier and compared; they are never
/// parsed, interpreted or given meaning. A nonce, a digest over a request body, a
/// domain-separated message built by <see cref="AnchorSignatureContext"/> -- all are the
/// same to this method, and the choice belongs to whoever integrates it.
/// </para>
/// <para>
/// That is a deliberate limit rather than an omission, and it has a consequence worth
/// stating plainly: <b>this type cannot tell a signature made for one operation from a
/// signature made for another.</b> It reports that a key signed some bytes. Binding those
/// bytes to a purpose, to a session and to a moment is the caller's work -- the library
/// would have to fix a message format to do it, and a fixed format is exactly what a
/// library serving different protocols must not impose.
/// </para>
///
/// <para><b>Freshness is likewise the caller's</b></para>
/// <para>
/// A signature that verified here may be one produced a year ago. Nothing in the bytes
/// says when they were signed. A value the caller issued, stored and accepts only once is
/// what makes a verified signature mean "now", and this type has no view of that store.
/// </para>
///
/// <para><b>Apple assertions do not come through here</b></para>
/// <para>
/// An App Attest assertion is not a bare signature: it is a small CBOR envelope carrying
/// the signature alongside authenticator data, and its counter and application identity
/// are checked as part of the assertion, not afterwards. Use
/// <see cref="AppleAssertionVerifier"/> for those, and this type for a raw signature --
/// which is what an Android Keystore key produces.
/// </para>
/// </remarks>
public static class DeviceSignature
{
    /// <summary>
    /// Verifies an ECDSA-SHA256 signature over <paramref name="signedData"/>.
    /// </summary>
    /// <param name="signature">
    /// The signature, DER encoded -- the form <c>SHA256withECDSA</c> produces on Android
    /// and the form this library reads everywhere else.
    /// </param>
    /// <param name="signedData">
    /// The bytes the device signed. Any length: the digest is taken here, exactly as the
    /// signing side takes it, so a caller is never forced to pre-hash.
    /// </param>
    /// <param name="publicKeyDer">
    /// The attested public key, as <c>SubjectPublicKeyInfo</c> DER -- the value
    /// <see cref="AttestationResult.PublicKeyDer"/> returned at enrollment.
    /// </param>
    /// <param name="algorithm">
    /// The algorithm to check under. Defaults to
    /// <see cref="DeviceSignatureAlgorithm.EcdsaSha256"/>, and comes from the caller rather
    /// than from anything the request carried.
    /// </param>
    /// <returns>
    /// A result that is valid only when the key parsed and the signature verified over
    /// those exact bytes.
    /// </returns>
    /// <remarks>
    /// An unreadable key, an unknown algorithm and a wrong signature all report
    /// <see cref="AttestationFailureReason.SignatureInvalid"/>. They are not separated
    /// because the distinction is of no use to a caller at this point and telling them
    /// apart tells an attacker which part of the triple it got wrong.
    /// </remarks>
    public static SignatureVerificationResult Verify(
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte> signedData,
        ReadOnlyMemory<byte> publicKeyDer,
        DeviceSignatureAlgorithm algorithm = DeviceSignatureAlgorithm.EcdsaSha256)
    {
        // An undefined value is a refusal rather than a fall back to the default. A caller
        // that passed one has a field it never populated, and answering it as though the
        // default had been chosen would hide that from them permanently.
        if (algorithm != DeviceSignatureAlgorithm.EcdsaSha256)
        {
            return SignatureVerificationResult.Failure(AttestationFailureReason.SignatureInvalid);
        }

        if (signature.IsEmpty || publicKeyDer.IsEmpty)
        {
            return SignatureVerificationResult.Failure(AttestationFailureReason.SignatureInvalid);
        }

        if (!EcKeyTools.TryReadEcPublicKey(publicKeyDer.Span, out ECPublicKeyParameters? key))
        {
            return SignatureVerificationResult.Failure(AttestationFailureReason.SignatureInvalid);
        }

        return EcKeyTools.VerifyEcdsaSha256(key!, signedData.Span, signature.Span)
            ? SignatureVerificationResult.Success()
            : SignatureVerificationResult.Failure(AttestationFailureReason.SignatureInvalid);
    }
}
