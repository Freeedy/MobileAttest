using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MobileAttest.Abstractions;
using MobileAttest.Internal;
using Org.BouncyCastle.Crypto.Parameters;

namespace MobileAttest.Apple;

/// <summary>
/// Verifies an Apple App Attest assertion: the per-request proof that the key attested at
/// enrolment, and no other, signed this particular request.
/// </summary>
/// <remarks>
/// <para><b>The steps run in order and stop at the first failure</b></para>
/// <list type="number">
///   <item>the relying-party identifier hash is the one stored for this application</item>
///   <item>the signature verifies under the public key stored when the key was attested</item>
///   <item>the signature counter is strictly above the one stored from the last assertion</item>
/// </list>
/// <para><b>What the signature is made over</b></para>
/// <para>
/// The nonce is <c>SHA-256(authenticatorData ‖ clientDataHash)</c>, and the device signs that
/// nonce as a message -- so the value under the signature is <c>SHA-256(nonce)</c>. This is
/// measured on a real device capture rather than read off a specification whose wording admits
/// two readings; <see cref="AppleAssertionDigest"/> carries the measurement and the date.
/// </para>
/// <para>
/// The other reading is refused rather than also attempted. Trying both and accepting whichever
/// verified would double the set of signatures this library calls valid and would undo the
/// separation between one signed message and another, which is the property the whole check
/// exists for.
/// </para>
/// <para><b>No certificate takes part, so no root and no clock do either</b></para>
/// <para>
/// Attestation ends with a chain validated to a pinned root; assertion starts from what that
/// produced. The only key involved is the one the caller stored, so there is nothing to pin,
/// nothing to fetch and no validity window to judge. This verifier therefore takes no
/// evaluation instant, unlike <see cref="AppleAppAttestVerifier"/>: adding one would advertise
/// a date check that is not performed. Binding a request to one exchange is the caller's
/// nonce, which reaches this library already folded into
/// <c>clientDataHash</c>.
/// </para>
/// <para><b>The counter is judged last, and that ordering is the point of it</b></para>
/// <para>
/// The counter sits inside the authenticator data, which arrives from the device. Until the
/// signature has been checked, that number is a value an attacker picked; acting on it before
/// step 2 would mean a replayed assertion could be waved through by naming a large counter, or
/// a genuine key locked out by naming a small one. So the counter is only read after the
/// signature has shown that the attested key produced these exact bytes.
/// </para>
/// <para>
/// The comparison is strictly greater, never equal. An equal counter is what a cloned key
/// produces: the copy advances its own counter independently, so the same value arriving twice
/// says two devices hold the key.
/// </para>
/// <para><b>The counter is returned, not stored</b></para>
/// <para>
/// <see cref="AssertionResult.NewSignCount"/> is what the caller must persist in place of the
/// value it passed in. This library keeps no state between calls, so a caller that does not
/// store it has no clone detection at all -- every request would be compared against the same
/// stale counter.
/// </para>
/// <para>
/// A caller that also keeps a replay cache must key it on the credential identifier and the
/// counter, <b>never on the raw bytes of the assertion object</b>. The decoder accepts
/// indefinite-length CBOR, so one logical assertion can arrive under more than one byte
/// sequence and a cache keyed on bytes would miss the repeat.
/// </para>
/// <para><b>A caller receives one reason, never a list</b></para>
/// <para>
/// As on the attestation side: a list of everything wrong with an assertion describes the
/// device that sent it, and a rejection must not hand that back to whoever sent it.
/// </para>
/// </remarks>
public sealed class AppleAssertionVerifier : IAssertionVerifier
{
    private readonly byte[] _expectedRpIdHash;
    private readonly IAppleCborReader _cborReader;
    private readonly AppleAssertionDigest _digest;

    /// <summary>
    /// Creates a verifier for one application identity, hashing it once here.
    /// </summary>
    /// <param name="appId">
    /// The application identity the key was attested under, in the form
    /// <c>"{teamId}.{bundleId}"</c> -- the value <see cref="AttestationResult.AppId"/> carried
    /// when the key was enrolled.
    /// </param>
    /// <exception cref="ArgumentException"><paramref name="appId"/> is empty or whitespace.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="appId"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// The hash is derived here, at construction, and not on each verification. Recomputing it
    /// per request would put a value the caller configured back into the hot path of a check
    /// whose whole job is to compare against something settled at enrolment.
    /// </remarks>
    public AppleAssertionVerifier(string appId)
        : this(RpIdHashFor(appId))
    {
    }

    /// <summary>
    /// Creates a verifier over the relying-party identifier hash the caller stored.
    /// </summary>
    /// <param name="expectedRpIdHash">
    /// The 32-byte hash the assertion must carry: <c>SHA-256("{teamId}.{bundleId}")</c>.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="expectedRpIdHash"/> is not exactly 32 bytes.
    /// </exception>
    public AppleAssertionVerifier(ReadOnlyMemory<byte> expectedRpIdHash)
        : this(expectedRpIdHash, new AppleCborReader())
    {
    }

    /// <summary>
    /// Creates a verifier over a supplied decoder.
    /// </summary>
    /// <param name="expectedRpIdHash">
    /// The 32-byte hash the assertion must carry: <c>SHA-256("{teamId}.{bundleId}")</c>.
    /// </param>
    /// <param name="cborReader">The decoder for the assertion object.</param>
    /// <param name="digest">
    /// Which construction the signature is checked against. The default is the one that has
    /// been measured, so a caller that configures nothing is configured correctly.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="cborReader"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="expectedRpIdHash"/> is not exactly 32 bytes.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="digest"/> is not a defined value. This is a mistake in the calling code
    /// rather than bad input, so it is refused where it is configured rather than turning into
    /// a rejection on every request.
    /// </exception>
    /// <remarks>
    /// The hash length is checked here rather than at the comparison. A stored hash of the
    /// wrong length can never equal a 32-byte one, so a verifier built on it would refuse every
    /// device with <see cref="AttestationFailureReason.RpIdHashMismatch"/> and nothing would
    /// say that the configuration, not the traffic, was wrong.
    /// </remarks>
    public AppleAssertionVerifier(
        ReadOnlyMemory<byte> expectedRpIdHash,
        IAppleCborReader cborReader,
        AppleAssertionDigest digest = AppleAssertionDigest.NonceSignedAsMessage)
    {
        if (cborReader is null)
        {
            throw new ArgumentNullException(nameof(cborReader));
        }

        if (expectedRpIdHash.Length != AuthenticatorData.RpIdHashLength)
        {
            throw new ArgumentException(
                $"The expected relying-party identifier hash must be {AuthenticatorData.RpIdHashLength} bytes.",
                nameof(expectedRpIdHash));
        }

        if (digest is not AppleAssertionDigest.NonceSignedAsMessage)
        {
            throw new ArgumentOutOfRangeException(
                nameof(digest),
                digest,
                "Unknown assertion digest construction.");
        }

        _expectedRpIdHash = expectedRpIdHash.ToArray();
        _cborReader = cborReader;
        _digest = digest;
    }

    /// <inheritdoc />
    public Platform Platform => Platform.Apple;

    /// <inheritdoc />
    /// <remarks>
    /// The work is synchronous and the token is accepted only to satisfy the contract: this
    /// implementation performs no I/O, so there is nothing to abandon partway. Throwing on a
    /// cancelled token would add an exception the contract does not declare.
    /// </remarks>
    public Task<AssertionResult> VerifyAsync(
        ReadOnlyMemory<byte> assertionObject,
        ReadOnlyMemory<byte> clientDataHash,
        ReadOnlyMemory<byte> attestedPublicKeyDer,
        uint lastSignCount,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(Verify(assertionObject, clientDataHash, attestedPublicKeyDer, lastSignCount));

    private AssertionResult Verify(
        ReadOnlyMemory<byte> assertionObject,
        ReadOnlyMemory<byte> clientDataHash,
        ReadOnlyMemory<byte> attestedPublicKeyDer,
        uint lastSignCount)
    {
        // Decoding is not one of the three steps: it answers "are these bytes an assertion
        // object at all", and the steps answer "is this assertion genuine". They are kept
        // apart because their failure reasons are, too.
        if (!_cborReader.TryReadAssertionObject(assertionObject, out AppleAssertionObject? assertion))
        {
            return AssertionResult.Failure(AttestationFailureReason.MalformedAttestationObject);
        }

        // The raw bytes are what the signature covers. Re-encoding the parsed fields to
        // rebuild the message would verify a signature over something the device never sent.
        ReadOnlyMemory<byte> rawAuthenticatorData = assertion!.AuthenticatorData;

        // The assertion shape, and only it. A real iOS assertion is exactly 37 bytes and sets
        // the attested-credential-data flag while carrying none, so the flag is not read as a
        // description of the payload and anything longer is refused rather than trimmed.
        if (!AuthenticatorData.TryParse(
                rawAuthenticatorData.Span,
                AuthenticatorDataShape.Assertion,
                out AuthenticatorData? authenticatorData))
        {
            return AssertionResult.Failure(AttestationFailureReason.MalformedAuthenticatorData);
        }

        // Step 1. Constant time, like every comparison on material a device influenced.
        if (!FixedTime.FixedTimeEquals(authenticatorData!.RpIdHash.ToArray(), _expectedRpIdHash))
        {
            return AssertionResult.Failure(AttestationFailureReason.RpIdHashMismatch);
        }

        // Step 2. A stored key that will not parse is the caller's own record being unreadable
        // rather than a device misbehaving, but it fails at the same step and for the same
        // practical reason: no signature can be verified under a key that cannot be read. The
        // reason names the step that could not be completed and claims nothing about the
        // device -- an operator seeing every request refused this way should suspect the
        // stored key before suspecting the traffic.
        if (!EcKeyTools.TryReadEcPublicKey(attestedPublicKeyDer.Span, out ECPublicKeyParameters? attestedKey))
        {
            return AssertionResult.Failure(AttestationFailureReason.SignatureInvalid);
        }

        // The nonce, built over the authenticator data exactly as it arrived. The device signs
        // this value as a message, so the signer digests it again -- see AppleAssertionDigest,
        // which records that this is measured device behaviour and not a reading of prose.
        //
        // An empty client data hash is not a special case: it produces a different nonce, so
        // the signature simply does not verify. That is the honest answer -- a caller that
        // passed one bound the request to nothing, and this check already refuses it.
        byte[] nonce = DigestFor(rawAuthenticatorData.Span, clientDataHash.Span);

        if (!EcKeyTools.VerifyEcdsaSha256(attestedKey!, nonce, assertion.Signature.Span))
        {
            return AssertionResult.Failure(AttestationFailureReason.SignatureInvalid);
        }

        // Step 3. Strictly greater, and only now that the signature has shown the attested key
        // produced this counter. Equal means a clone advanced its own copy to the same value;
        // lower means the counter went backwards, which one device cannot do.
        if (authenticatorData.SignCount <= lastSignCount)
        {
            return AssertionResult.Failure(AttestationFailureReason.SignCountNotIncreased);
        }

        return AssertionResult.Success(authenticatorData.SignCount);
    }

    /// <summary>
    /// Builds the message the signature is verified over.
    /// </summary>
    /// <param name="rawAuthenticatorData">The authenticator data exactly as it arrived.</param>
    /// <param name="clientDataHash">The digest binding the assertion to this request.</param>
    /// <returns>The bytes handed to the signer, which digests them once more.</returns>
    /// <remarks>
    /// Only one construction is produced, never two. A verifier that built both and accepted
    /// whichever verified would widen the set of signatures it calls valid, and would give up
    /// the guarantee that a signature made for one message cannot pass as another.
    /// </remarks>
    private byte[] DigestFor(
        ReadOnlySpan<byte> rawAuthenticatorData,
        ReadOnlySpan<byte> clientDataHash) =>
        _digest switch
        {
            AppleAssertionDigest.NonceSignedAsMessage =>
                EcKeyTools.Sha256(rawAuthenticatorData, clientDataHash),

            // Unreachable: the constructor refuses anything else. It is written rather than
            // defaulted so that adding a value to the enum without handling it here fails
            // loudly instead of silently taking a construction nobody chose.
            _ => throw new InvalidOperationException("Unknown assertion digest construction."),
        };

    /// <summary>Derives the relying-party identifier hash from an application identity.</summary>
    /// <param name="appId">The identity, in the form <c>"{teamId}.{bundleId}"</c>.</param>
    /// <returns>The 32-byte hash an assertion for that application carries.</returns>
    private static byte[] RpIdHashFor(string appId)
    {
        if (appId is null)
        {
            throw new ArgumentNullException(nameof(appId));
        }

        if (appId.Length == 0 || string.IsNullOrWhiteSpace(appId))
        {
            throw new ArgumentException(
                "The application identity must be the \"{teamId}.{bundleId}\" the key was attested under.",
                nameof(appId));
        }

        return EcKeyTools.Sha256(Encoding.UTF8.GetBytes(appId));
    }
}
