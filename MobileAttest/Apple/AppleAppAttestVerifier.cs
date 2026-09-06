using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MobileAttest.Abstractions;
using MobileAttest.Internal;
using MobileAttest.Trust;
using Org.BouncyCastle.X509;

namespace MobileAttest.Apple;

/// <summary>
/// Verifies an Apple App Attest attestation end to end: the object, the certificate chain,
/// and the seven checks Apple's procedure defines over what the chain carries.
/// </summary>
/// <remarks>
/// <para><b>The steps run in order and stop at the first failure</b></para>
/// <list type="number">
///   <item>the attestation statement format is the one this library verifies</item>
///   <item>the certificate chain validates to a root the caller pinned</item>
///   <item>the nonce in the credential certificate is the one the challenge derives</item>
///   <item>the relying-party identifier hash names a configured application</item>
///   <item>the AAGUID names an environment the caller's policy accepts</item>
///   <item>the key identifier recomputed from the certificate matches both copies sent</item>
///   <item>the signature counter is zero, as it must be for a freshly attested key</item>
/// </list>
/// <para>
/// A caller receives one <see cref="AttestationFailureReason"/>, never a list. A list of
/// everything wrong with an attestation is a description of the device that sent it, and a
/// rejection must not hand that back to whoever sent it.
/// </para>
/// <para><b>The order is a security property, not a convenience</b></para>
/// <para>
/// The chain runs before anything reads the certificate, so every value used afterwards --
/// the nonce, the attested public key -- comes from a certificate Apple signed rather than
/// from bytes a device chose. The nonce runs before the application and environment checks,
/// so the authenticator data those checks read has already been bound to the challenge this
/// server issued; without that ordering they would be reading a replayable blob.
/// </para>
/// <para><b>Validity is asked about an instant the caller names</b></para>
/// <para>
/// The question this verifier answers about certificate dates is "was this chain valid at
/// that instant", not "is it valid now". The instant is a parameter on
/// <see cref="VerifyAsync(AttestationRequest, DateTimeOffset, CancellationToken)"/>, so one
/// verifier can answer for two different instants and answering for a past one needs no
/// substitute clock. The overload without it reads the <see cref="TimeProvider"/> the
/// constructor was given, which defaults to the system clock.
/// </para>
/// <para>
/// <b>That instant must come from the server's own record</b> -- the moment the attestation
/// was received -- and never from anything the device sent or from a value read out of the
/// attestation itself. A caller that took it from the payload would let an old attestation be
/// replayed with the instant that made it valid attached. This library cannot enforce that;
/// it is the caller's obligation, which is why it is written here.
/// </para>
/// <para>
/// Freshness is a separate mechanism and is not what this instant provides. An attestation is
/// bound to one exchange by the challenge -- server issued, short lived, and checked at step 3
/// -- while the evaluation instant only decides which certificates were inside their validity
/// window. Neither substitutes for the other.
/// </para>
/// <para><b>The roots are the caller's</b></para>
/// <para>
/// Anchors come from <see cref="AppleAttestOptions.PinnedRootCertificates"/> and from
/// nowhere else. This library carries no Apple root and holds no address to fetch one from,
/// so a caller who configures none gets
/// <see cref="AttestationFailureReason.RootNotPinned"/> for every device. An unconfigured
/// trust store fails closed, because the alternative is a verifier reporting success while
/// checking a chain against nothing.
/// </para>
/// <para>
/// The intermediate is not configuration either: it arrives inside the attestation object's
/// own <c>x5c</c>, so pinning the root is the whole of what a caller supplies.
/// </para>
/// <para><b>The environment comes only from the AAGUID</b></para>
/// <para>
/// Nothing a client says about which build it is decides this, and
/// <see cref="AppleAttestationRequest"/> deliberately carries no field for it. The AAGUID
/// sits inside the authenticator data, which the nonce -- and therefore Apple's signature
/// over the credential certificate -- covers.
/// </para>
/// <para><b>The receipt is returned, not verified</b></para>
/// <para>
/// It is carried through to the caller as the bytes the object held. Checking it means
/// calling Apple's server, which this library does not do; a caller that wants it verified
/// has the material to do so.
/// </para>
/// </remarks>
public sealed class AppleAppAttestVerifier : IAttestationVerifier
{
    /// <summary>The only attestation statement format this verifier accepts.</summary>
    public const string AttestationFormat = "apple-appattest";

    /// <summary>
    /// The AAGUID a production key carries: an ASCII label in a fixed 16-byte field, zero
    /// padded.
    /// </summary>
    private static readonly byte[] ProductionAaguid = Aaguid("appattest");

    /// <summary>The AAGUID a development key carries, which fills the field exactly.</summary>
    private static readonly byte[] DevelopmentAaguid = Aaguid("appattestdevelop");

    /// <summary>The value the signature counter must hold in an attestation.</summary>
    private const uint AttestationSignCount = 0;

    private readonly AppleAttestOptions _options;
    private readonly IAppleCborReader _cborReader;
    private readonly TimeProvider _defaultTimeProvider;
    private readonly ChainValidationPolicy _chainPolicy;

    /// <summary>Creates a verifier whose default evaluation instant is the system clock.</summary>
    /// <param name="options">The caller's policy, including the pinned roots.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    public AppleAppAttestVerifier(AppleAttestOptions options)
        : this(options, TimeProvider.System)
    {
    }

    /// <summary>Creates a verifier whose default evaluation instant comes from a supplied clock.</summary>
    /// <param name="options">The caller's policy, including the pinned roots.</param>
    /// <param name="defaultTimeProvider">
    /// Where the overload without an explicit instant reads one from.
    /// </param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    public AppleAppAttestVerifier(AppleAttestOptions options, TimeProvider defaultTimeProvider)
        : this(options, defaultTimeProvider, new AppleCborReader(), new ChainValidationPolicy())
    {
    }

    /// <summary>Creates a verifier over a supplied decoder and chain limits.</summary>
    /// <param name="options">The caller's policy, including the pinned roots.</param>
    /// <param name="defaultTimeProvider">
    /// Where the overload without an explicit instant reads one from.
    /// </param>
    /// <param name="cborReader">The decoder for the attestation object.</param>
    /// <param name="chainPolicy">The limits the chain validation runs under.</param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="chainPolicy"/> is out of range.</exception>
    /// <remarks>
    /// A built chain validator is deliberately not accepted here. One carries its own clock,
    /// fixed when it was constructed, and a verifier holding it could not honour the
    /// evaluation instant its own callers pass -- it would take the parameter and quietly
    /// answer for a different moment. The limits are taken instead, and the validator is built
    /// per call around the instant that call named.
    /// </remarks>
    public AppleAppAttestVerifier(
        AppleAttestOptions options,
        TimeProvider defaultTimeProvider,
        IAppleCborReader cborReader,
        ChainValidationPolicy chainPolicy)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (defaultTimeProvider is null)
        {
            throw new ArgumentNullException(nameof(defaultTimeProvider));
        }

        if (cborReader is null)
        {
            throw new ArgumentNullException(nameof(cborReader));
        }

        if (chainPolicy is null)
        {
            throw new ArgumentNullException(nameof(chainPolicy));
        }

        chainPolicy.Validate();

        _options = options;
        _cborReader = cborReader;
        _defaultTimeProvider = defaultTimeProvider;
        _chainPolicy = chainPolicy;
    }

    /// <inheritdoc />
    public Platform Platform => Platform.Apple;

    /// <inheritdoc />
    /// <remarks>
    /// Evaluates at the instant the constructor's <see cref="TimeProvider"/> reports. Prefer
    /// <see cref="VerifyAsync(AttestationRequest, DateTimeOffset, CancellationToken)"/>, which
    /// makes the instant visible at the call site and lets one verifier answer for more than
    /// one moment.
    /// </remarks>
    public Task<AttestationResult> VerifyAsync(
        AttestationRequest request,
        CancellationToken cancellationToken = default) =>
        VerifyAsync(request, _defaultTimeProvider.GetUtcNow(), cancellationToken);

    /// <summary>
    /// Verifies one attestation as of a named instant.
    /// </summary>
    /// <param name="request">The attestation to verify.</param>
    /// <param name="evaluationTime">
    /// The instant the certificate chain's validity is judged at -- "was this valid then",
    /// not "is it valid now".
    /// <para>
    /// It must be the server's own record of when the attestation was received. Taking it
    /// from the device, or from a value read out of the attestation, would let an expired
    /// attestation be replayed together with the instant that makes it pass. Nothing here can
    /// check where the value came from, so it is the caller's obligation.
    /// </para>
    /// <para>
    /// This is not a freshness check. Binding an attestation to one exchange is the
    /// challenge's job, and the challenge is compared at step 3 regardless of this value.
    /// </para>
    /// </param>
    /// <param name="cancellationToken">Cancels the verification.</param>
    /// <returns>
    /// The outcome. A rejected attestation is reported as a failed
    /// <see cref="AttestationResult"/>, not as an exception.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is <see langword="null"/>.</exception>
    /// <remarks>
    /// The work is synchronous and the token is accepted only to satisfy the contract: this
    /// implementation performs no I/O, so there is nothing to abandon partway. Throwing on a
    /// cancelled token would add an exception the contract does not declare.
    /// </remarks>
    public Task<AttestationResult> VerifyAsync(
        AttestationRequest request,
        DateTimeOffset evaluationTime,
        CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return Task.FromResult(Verify(request, evaluationTime));
    }

    private AttestationResult Verify(AttestationRequest request, DateTimeOffset evaluationTime)
    {
        if (request is not AppleAttestationRequest apple)
        {
            // A request from another platform reaching an Apple verifier is a wiring mistake
            // in the caller. It is answered rather than thrown so that a dispatcher holding
            // several verifiers cannot be brought down by routing one request wrongly.
            return Failure(AttestationFailureReason.UnsupportedAttestationFormat);
        }

        // Decoding. Neither of these is one of the seven checks: they answer "are these
        // bytes an attestation object at all", and the checks answer "is this attestation
        // genuine". They are kept apart because their failure reasons are, too.
        if (!_cborReader.TryReadAttestationObject(
                apple.AttestationObject,
                out AppleAttestationObject? attestation))
        {
            return Failure(AttestationFailureReason.MalformedAttestationObject);
        }

        // Step 1. The format is checked rather than assumed: the decoder returns whatever
        // string the object carried and deliberately does not judge it.
        if (!string.Equals(attestation!.Format, AttestationFormat, StringComparison.Ordinal))
        {
            return Failure(AttestationFailureReason.UnsupportedAttestationFormat);
        }

        // The raw bytes are kept as well as the parsed structure. The nonce is a digest over
        // the authenticator data exactly as it arrived, so re-encoding the parsed fields to
        // rebuild it would compute the digest of something the device never sent.
        ReadOnlyMemory<byte> rawAuthenticatorData = attestation.AuthenticatorData;

        if (!AuthenticatorData.TryParse(
                rawAuthenticatorData.Span,
                AuthenticatorDataShape.Attestation,
                out AuthenticatorData? authenticatorData))
        {
            return Failure(AttestationFailureReason.MalformedAuthenticatorData);
        }

        // Step 2. Everything read after this point comes from a certificate that validated,
        // never from the request. The validator is built here rather than held as a field,
        // because the instant it judges dates against belongs to this call.
        ChainValidationResult chain = new PkixChainValidator(
                new FixedInstant(evaluationTime),
                _chainPolicy)
            .Validate(
                ToDerChain(attestation.X5c),
                _options.PinnedRootCertificates);

        if (!chain.IsValid)
        {
            return Failure(chain.Reason);
        }

        X509Certificate credentialCertificate = chain.ValidatedPath[0];

        // Step 3.
        AttestationFailureReason nonceFailure = CheckNonce(
            credentialCertificate,
            rawAuthenticatorData.Span,
            apple.Challenge.Span);

        if (nonceFailure != AttestationFailureReason.None)
        {
            return Failure(nonceFailure);
        }

        // Step 4.
        if (!TryMatchApplication(
                authenticatorData!.RpIdHash.Span,
                out string? appId,
                out AttestationFailureReason applicationFailure))
        {
            return Failure(applicationFailure);
        }

        // Step 5.
        if (!TryReadEnvironment(
                authenticatorData.Aaguid.Span,
                out AttestationEnvironment environment))
        {
            // An AAGUID that is neither of the two Apple defines leaves the environment
            // unknown, and an unknown environment may not travel on a successful result: a
            // caller reading Environment would be told "we could not tell" by a value that
            // also means "this platform has no such notion". Rejecting is the only answer
            // that cannot be misread. It is decided before policy so that the reason never
            // claims a development key was seen when nothing identifiable was.
            return Failure(AttestationFailureReason.MalformedAuthenticatorData);
        }

        if (_options.RequireProduction && environment != AttestationEnvironment.Production)
        {
            return Failure(AttestationFailureReason.DevelopmentKeyInProduction);
        }

        // Step 6.
        if (!EcKeyTools.TryComputeKeyId(
                credentialCertificate.SubjectPublicKeyInfo,
                out byte[]? keyId))
        {
            // The attested key is not one an App Attest key identifier can be derived from,
            // so no identifier the device sent can match it.
            return Failure(AttestationFailureReason.KeyIdMismatch);
        }

        // Two comparisons, not one. The credential identifier lives in the authenticator
        // data and the key identifier arrives beside the object, and both are the device's
        // claims about a key whose real identifier has just been recomputed from Apple's
        // certificate. Checking only one of them would leave the other free to name a
        // different key than the one that was verified.
        if (!FixedTime.FixedTimeEquals(keyId, authenticatorData.CredentialId.ToArray()) ||
            !FixedTime.FixedTimeEquals(keyId, apple.KeyId.ToArray()))
        {
            return Failure(AttestationFailureReason.KeyIdMismatch);
        }

        // Step 7. A counter that is not zero says this key has signed before, which a key
        // being attested for the first time cannot have done.
        if (authenticatorData.SignCount != AttestationSignCount)
        {
            return Failure(AttestationFailureReason.SignCountInvalid);
        }

        return AttestationResult.Success(
            Platform.Apple,
            environment,

            // The identifier recomputed from the certificate, not either copy the device
            // sent. They were just shown to be equal, so this changes no value -- it changes
            // where the stored value came from, which is the difference between a caller
            // storing what Apple attested and storing what a device asked us to store.
            keyId!,
            credentialCertificate.SubjectPublicKeyInfo.GetDerEncoded(),
            appId,
            authenticatorData.SignCount,
            attestation.Receipt);
    }

    /// <summary>
    /// Checks that the credential certificate's nonce is the one this challenge derives.
    /// </summary>
    /// <param name="credentialCertificate">The validated leaf.</param>
    /// <param name="rawAuthenticatorData">The authenticator data exactly as it arrived.</param>
    /// <param name="challenge">The challenge this server issued.</param>
    /// <returns>
    /// <see cref="AttestationFailureReason.None"/> when the nonce matched, otherwise the
    /// reason it did not.
    /// </returns>
    /// <remarks>
    /// This is the step that makes an attestation unreplayable. The nonce Apple signed into
    /// the certificate is <c>SHA-256(authenticatorData ‖ SHA-256(challenge))</c>, so an
    /// attestation captured from one enrolment cannot be presented against another
    /// challenge, and the authenticator data every later step reads is bound to this
    /// exchange rather than merely well formed.
    /// </remarks>
    private static AttestationFailureReason CheckNonce(
        X509Certificate credentialCertificate,
        ReadOnlySpan<byte> rawAuthenticatorData,
        ReadOnlySpan<byte> challenge)
    {
        if (!AppleNonceExtension.TryRead(credentialCertificate, out byte[]? nonce))
        {
            return AttestationFailureReason.MalformedAttestationExtension;
        }

        byte[] expected = EcKeyTools.Sha256(
            rawAuthenticatorData,
            EcKeyTools.Sha256(challenge));

        // An empty challenge derives a perfectly good digest, and a caller that passed one
        // would be comparing against a value it never issued. That is a mismatch here rather
        // than a special case: nothing about it needs its own reason, and the comparison
        // already refuses it.
        return FixedTime.FixedTimeEquals(nonce, expected)
            ? AttestationFailureReason.None
            : AttestationFailureReason.NonceMismatch;
    }

    /// <summary>
    /// Finds the configured application whose identity hashes to the relying-party
    /// identifier hash.
    /// </summary>
    /// <param name="rpIdHash">The hash carried by the authenticator data.</param>
    /// <param name="appId">The application identity that matched, or <see langword="null"/>.</param>
    /// <param name="failureReason">Why no application matched.</param>
    /// <returns>Whether one matched.</returns>
    /// <remarks>
    /// <para>
    /// The comparison runs the other way round from how it reads: the hash cannot be
    /// reversed, so each configured application identity is hashed and offered to it. An
    /// empty allowlist therefore has nothing to offer and is refused as
    /// <see cref="AttestationFailureReason.BundleIdNotAllowed"/> -- an empty allowlist is
    /// not "allow anything", it is "allow nothing".
    /// </para>
    /// <para>
    /// <b>A non-empty allowlist that matches nothing is reported as
    /// <see cref="AttestationFailureReason.RpIdHashMismatch"/>, always.</b> It is tempting to
    /// answer <c>BundleIdNotAllowed</c> when the team identifier looks right and the bundle
    /// does not, but that distinction cannot be made: the hash covers both halves and gives
    /// back one bit. Reporting <c>BundleIdNotAllowed</c> would be claiming to know which
    /// bundle identifier the device attested, which nothing here establishes. The reason
    /// given is the measurement that was actually made.
    /// </para>
    /// </remarks>
    private bool TryMatchApplication(
        ReadOnlySpan<byte> rpIdHash,
        out string? appId,
        out AttestationFailureReason failureReason)
    {
        appId = null;

        IReadOnlyCollection<string>? allowlist = _options.BundleIdAllowlist;

        if (allowlist is null || allowlist.Count == 0)
        {
            failureReason = AttestationFailureReason.BundleIdNotAllowed;
            return false;
        }

        byte[] presented = rpIdHash.ToArray();

        foreach (string bundleId in allowlist)
        {
            if (bundleId is null)
            {
                continue;
            }

            string candidate = _options.TeamId + "." + bundleId;

            if (FixedTime.FixedTimeEquals(
                    presented,
                    EcKeyTools.Sha256(Encoding.UTF8.GetBytes(candidate))))
            {
                appId = candidate;
                failureReason = AttestationFailureReason.None;
                return true;
            }
        }

        failureReason = AttestationFailureReason.RpIdHashMismatch;
        return false;
    }

    /// <summary>
    /// Maps an AAGUID onto the environment it names.
    /// </summary>
    /// <param name="aaguid">The AAGUID carried by the authenticator data.</param>
    /// <param name="environment">The environment named, when one was.</param>
    /// <returns>Whether the AAGUID was one of the two Apple defines.</returns>
    /// <remarks>
    /// The comparison is constant time like the others, though nothing secret is being
    /// compared: it is one code path either way, and a comparison that is fast because
    /// somebody judged the value harmless is a judgement that has to be re-made every time
    /// the value moves.
    /// </remarks>
    private static bool TryReadEnvironment(
        ReadOnlySpan<byte> aaguid,
        out AttestationEnvironment environment)
    {
        byte[] presented = aaguid.ToArray();

        if (FixedTime.FixedTimeEquals(presented, ProductionAaguid))
        {
            environment = AttestationEnvironment.Production;
            return true;
        }

        if (FixedTime.FixedTimeEquals(presented, DevelopmentAaguid))
        {
            environment = AttestationEnvironment.Development;
            return true;
        }

        environment = AttestationEnvironment.Unknown;
        return false;
    }

    /// <summary>Builds an AAGUID from its ASCII label, zero padded to the field width.</summary>
    private static byte[] Aaguid(string label)
    {
        byte[] value = new byte[AuthenticatorData.AaguidLength];
        Encoding.ASCII.GetBytes(label).CopyTo(value, 0);
        return value;
    }

    /// <summary>Copies the object's chain into the form the chain validator takes.</summary>
    /// <remarks>
    /// Every element is attacker supplied and may be empty; the validator answers such an
    /// element with a reason, so nothing is filtered out here. Dropping a bad element would
    /// change the chain the device sent into a different chain and validate that instead.
    /// </remarks>
    private static IReadOnlyList<byte[]> ToDerChain(IReadOnlyList<ReadOnlyMemory<byte>> chain)
    {
        byte[][] der = new byte[chain.Count][];

        for (int i = 0; i < der.Length; i++)
        {
            der[i] = chain[i].ToArray();
        }

        return der;
    }

    private static AttestationResult Failure(AttestationFailureReason reason) =>
        AttestationResult.Failure(Platform.Apple, reason);

    /// <summary>
    /// Presents one instant as a clock, so the chain validator's existing contract can be
    /// asked "was this valid then" without that contract changing.
    /// </summary>
    /// <remarks>
    /// The validator reads its instant from a <see cref="TimeProvider"/> given at
    /// construction. Rather than change that shape -- it is shared with the Android path and
    /// with callers outside this library -- the instant this call was given is handed over as
    /// a clock that reports it. Constructing both per call costs two small objects beside a
    /// certificate parse and a signature check.
    /// </remarks>
    private sealed class FixedInstant : TimeProvider
    {
        private readonly DateTimeOffset _instant;

        internal FixedInstant(DateTimeOffset instant) => _instant = instant;

        public override DateTimeOffset GetUtcNow() => _instant;
    }
}
