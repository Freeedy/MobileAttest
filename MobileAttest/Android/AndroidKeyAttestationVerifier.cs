using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MobileAttest.Abstractions;
using MobileAttest.Trust;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.X509;

namespace MobileAttest.Android;

/// <summary>
/// Verifies an Android Key Attestation end to end: the certificate chain, the key
/// attestation extension, and the caller's policy over what the extension says.
/// </summary>
/// <remarks>
/// <para><b>What this type does and does not decide</b></para>
/// <para>
/// It joins three parts that each already have an owner -- the chain engine, the extension
/// parser and <see cref="AndroidAttestationPolicy"/> -- and turns their answers into one
/// <see cref="AttestationResult"/>. It holds no rule of its own beyond the order those parts
/// run in, which is why the interesting cases are testable against the policy directly,
/// without a certificate.
/// </para>
/// <para><b>The roots are the caller's</b></para>
/// <para>
/// The anchors come from <see cref="AndroidAttestOptions.PinnedRootCertificates"/> and from
/// nowhere else. This library carries no Google root and holds no address to fetch one from,
/// so a caller who configures none gets
/// <see cref="AttestationFailureReason.RootNotPinned"/> for every device. That is deliberate:
/// an unconfigured trust store must fail closed, because the alternative is a verifier that
/// reports success while checking a chain against nothing.
/// </para>
/// <para>
/// <see cref="AndroidAttestOptions.Validate"/> is not called here. It throws, and a
/// configuration mistake should surface where the options are built rather than as an
/// exception out of a request path -- and the one mistake that matters most, an empty anchor
/// set, is already a rejection here rather than a pass.
/// </para>
/// <para><b>Revocation is not consulted</b></para>
/// <para>
/// Nothing in this method touches the network. Google's attestation revocation status list is
/// a separate mechanism with its own source and its own failure modes, and it is not part of
/// this type.
/// </para>
/// </remarks>
public sealed class AndroidKeyAttestationVerifier : IAttestationVerifier
{
    private readonly AndroidAttestOptions _options;
    private readonly ICertificateChainValidator _chainValidator;

    /// <summary>Creates a verifier reading certificate validity against the system clock.</summary>
    /// <param name="options">The caller's policy, including the pinned roots.</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is <see langword="null"/>.</exception>
    public AndroidKeyAttestationVerifier(AndroidAttestOptions options)
        : this(options, TimeProvider.System)
    {
    }

    /// <summary>Creates a verifier reading certificate validity against a supplied clock.</summary>
    /// <param name="options">The caller's policy, including the pinned roots.</param>
    /// <param name="timeProvider">The clock certificate validity dates are read against.</param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// The clock is injectable because an attestation chain is short lived. A test written
    /// against the machine clock passes today and fails on a date nobody wrote down, looking
    /// exactly like a defect in this code rather than like an expired input.
    /// </remarks>
    public AndroidKeyAttestationVerifier(AndroidAttestOptions options, TimeProvider timeProvider)
        : this(options, new PkixChainValidator(timeProvider))
    {
    }

    /// <summary>Creates a verifier over a supplied chain validator.</summary>
    /// <param name="options">The caller's policy, including the pinned roots.</param>
    /// <param name="chainValidator">The engine that validates the device chain against the pinned roots.</param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    public AndroidKeyAttestationVerifier(
        AndroidAttestOptions options,
        ICertificateChainValidator chainValidator)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        if (chainValidator is null)
        {
            throw new ArgumentNullException(nameof(chainValidator));
        }

        _options = options;
        _chainValidator = chainValidator;
    }

    /// <inheritdoc />
    public Platform Platform => Platform.Android;

    /// <inheritdoc />
    /// <remarks>
    /// The work is synchronous and the token is accepted only to satisfy the contract: this
    /// implementation performs no I/O, so there is nothing to abandon partway. Throwing on a
    /// cancelled token would add an exception the contract does not declare.
    /// </remarks>
    public Task<AttestationResult> VerifyAsync(
        AttestationRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request is null)
        {
            throw new ArgumentNullException(nameof(request));
        }

        return Task.FromResult(Verify(request));
    }

    private AttestationResult Verify(AttestationRequest request)
    {
        if (request is not AndroidAttestationRequest android)
        {
            // A request from another platform reaching an Android verifier is a wiring
            // mistake in the caller. It is answered rather than thrown so that a dispatcher
            // holding several verifiers cannot be brought down by routing one request wrongly.
            return AttestationResult.Failure(
                Platform.Android,
                AttestationFailureReason.UnsupportedAttestationFormat);
        }

        ChainValidationResult chain = _chainValidator.Validate(
            ToDerChain(android.CertificateChain),
            _options.PinnedRootCertificates);

        if (!chain.IsValid)
        {
            return AttestationResult.Failure(Platform.Android, chain.Reason);
        }

        // The leaf comes from the validated path rather than from the request, so the
        // certificate whose extension is read is the certificate that was actually verified.
        // Decoding the same bytes a second time would leave room for the two decodes to
        // disagree.
        X509Certificate leaf = chain.ValidatedPath[0];

        if (!KeyDescription.TryReadFrom(
                leaf,
                out KeyDescription? keyDescription,
                out AttestationFailureReason extensionFailure))
        {
            return AttestationResult.Failure(Platform.Android, extensionFailure);
        }

        AttestationFailureReason policyFailure = AndroidAttestationPolicy.Evaluate(
            keyDescription!,
            _options,
            android.Challenge);

        if (policyFailure != AttestationFailureReason.None)
        {
            return AttestationResult.Failure(Platform.Android, policyFailure);
        }

        // The SubjectPublicKeyInfo exactly as the certificate carries it, not a re-encoding of
        // the decoded key: a caller that computes this identifier from the same certificate
        // somewhere else has to arrive at the same bytes.
        byte[] publicKeyDer = leaf.SubjectPublicKeyInfo.GetDerEncoded();

        return AttestationResult.Success(
            Platform.Android,

            // Android has no equivalent of Apple's development and production AAGUIDs, so
            // there is nothing here to read an environment from. Mapping a verified boot
            // state onto Production would answer a question the record did not answer, and a
            // caller comparing an Android result with an Apple one would be misled by it.
            AttestationEnvironment.Unknown,
            Sha256(publicKeyDer),
            publicKeyDer,
            ReadPackageName(keyDescription!),

            // Android key attestation carries no signature counter and issues no receipt.
            signCount: 0,
            receipt: ReadOnlyMemory<byte>.Empty);
    }

    /// <summary>Copies the request's chain into the form the chain validator takes.</summary>
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

    /// <summary>
    /// Reads the package name the attestation is bound to, or <see langword="null"/> when the
    /// record named none.
    /// </summary>
    /// <remarks>
    /// This is reached only after <see cref="AndroidAttestationPolicy"/> has accepted the
    /// record, which means verified boot held and the signing digest was on the allowlist. The
    /// value is from the software-enforced list and is reported as an identifier, never as a
    /// hardware guarantee.
    /// </remarks>
    private static string? ReadPackageName(KeyDescription keyDescription)
    {
        AttestationApplicationId? applicationId =
            keyDescription.SoftwareEnforced.AttestationApplicationId;

        if (applicationId is null || applicationId.PackageInfos.Count == 0)
        {
            return null;
        }

        // A record may name several packages; the first is reported and the rest stay
        // readable on the parsed record. Which package is which is the caller's question, and
        // acceptance already rested on the signing digest rather than on this name.
        return applicationId.PackageInfos[0].PackageName;
    }

    private static byte[] Sha256(byte[] value)
    {
        Sha256Digest digest = new Sha256Digest();
        digest.BlockUpdate(value, 0, value.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }
}
