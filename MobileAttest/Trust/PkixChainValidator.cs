using System;
using System.Collections.Generic;
using System.IO;
using MobileAttest.Abstractions;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;

namespace MobileAttest.Trust;

/// <summary>
/// Validates a certificate chain with BouncyCastle's PKIX path validator.
/// </summary>
/// <remarks>
/// <para><b>The roots are yours</b></para>
/// <para>
/// This type holds no certificate, no default root and no address to fetch one from. The
/// anchors arrive as an argument on every call. A caller that supplies none gets a
/// rejection: an empty anchor set means there is nothing for the chain to be pinned to,
/// and treating that as a pass would let any device present its own root and be believed.
/// </para>
/// <para><b>The clock is injected</b></para>
/// <para>
/// Validity dates are read against a <see cref="TimeProvider"/> the caller supplies,
/// defaulting to the system clock. Reading the clock directly would make every test that
/// uses a real certificate fail the day that certificate expires -- and fail as though the
/// code were broken.
/// </para>
/// <para><b>Revocation is off, deliberately</b></para>
/// <para>
/// <see cref="PkixParameters.IsRevocationEnabled"/> is set to <see langword="false"/>, so
/// no CRL or OCSP fetch is attempted and verification never blocks on the network. Apple's
/// App Attest credential certificate lives about three days, which is shorter than any
/// revocation list would be useful over. Android's revocation is a separate mechanism with
/// its own status source and is not this type's business.
/// </para>
/// </remarks>
public sealed class PkixChainValidator : ICertificateChainValidator
{
    private readonly TimeProvider _timeProvider;
    private readonly int _maxChainLength;
    private readonly TimeSpan _clockSkew;

    /// <summary>Creates a validator on the system clock and the default limits.</summary>
    public PkixChainValidator()
        : this(TimeProvider.System, new ChainValidationPolicy())
    {
    }

    /// <summary>Creates a validator on a supplied clock and the default limits.</summary>
    /// <param name="timeProvider">The clock validity dates are read against.</param>
    /// <exception cref="ArgumentNullException"><paramref name="timeProvider"/> is <see langword="null"/>.</exception>
    public PkixChainValidator(TimeProvider timeProvider)
        : this(timeProvider, new ChainValidationPolicy())
    {
    }

    /// <summary>Creates a validator on a supplied clock and supplied limits.</summary>
    /// <param name="timeProvider">The clock validity dates are read against.</param>
    /// <param name="policy">The limits on attacker-supplied input.</param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="policy"/> is out of range.</exception>
    public PkixChainValidator(TimeProvider timeProvider, ChainValidationPolicy policy)
    {
        if (timeProvider is null)
        {
            throw new ArgumentNullException(nameof(timeProvider));
        }

        if (policy is null)
        {
            throw new ArgumentNullException(nameof(policy));
        }

        policy.Validate();

        // The limits are copied out rather than held by reference. The policy's properties
        // are settable, and a validator whose ceiling can be raised after it was checked is
        // a validator that was never really checked.
        _timeProvider = timeProvider;
        _maxChainLength = policy.MaxChainLength;
        _clockSkew = policy.ClockSkew;
    }

    /// <inheritdoc />
    public ChainValidationResult Validate(
        IReadOnlyList<byte[]> derChain,
        IReadOnlyList<X509Certificate> trustedRoots)
    {
        // The anchor set is examined first and unconditionally. Asked in this order, "no
        // pinned root" can only ever be answered with a rejection, whatever else is wrong
        // with the input -- there is no path through this method where an absent anchor
        // set reaches a success.
        if (trustedRoots is null || trustedRoots.Count == 0)
        {
            return ChainValidationResult.Failure(AttestationFailureReason.RootNotPinned);
        }

        List<X509Certificate> anchors = new List<X509Certificate>(trustedRoots.Count);

        foreach (X509Certificate root in trustedRoots)
        {
            // A null among the pinned roots is a mistake in the caller's configuration.
            // Failing closed keeps it from being the one anchor that quietly does nothing.
            if (root is null)
            {
                return ChainValidationResult.Failure(AttestationFailureReason.RootNotPinned);
            }

            anchors.Add(root);
        }

        if (derChain is null || derChain.Count == 0)
        {
            return ChainValidationResult.Failure(AttestationFailureReason.CertificateChainInvalid);
        }

        // Length is a property of the list, so an oversized chain is answered here, before
        // a single certificate is decoded. Decoding first would let a sender choose how
        // much ASN.1 parsing we do.
        if (derChain.Count > _maxChainLength)
        {
            return ChainValidationResult.Failure(AttestationFailureReason.CertificateChainInvalid);
        }

        List<X509Certificate> chain = new List<X509Certificate>(derChain.Count);

        foreach (byte[] der in derChain)
        {
            X509Certificate? certificate = TryReadCertificate(der);

            if (certificate is null)
            {
                return ChainValidationResult.Failure(AttestationFailureReason.CertificateChainInvalid);
            }

            chain.Add(certificate);
        }

        if (!TryResolveValidationInstant(chain, out DateTime validationInstant))
        {
            return ChainValidationResult.Failure(AttestationFailureReason.CertificateExpired);
        }

        try
        {
            HashSet<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();

            foreach (X509Certificate root in anchors)
            {
                trustAnchors.Add(new TrustAnchor(root, null));
            }

            PkixParameters parameters = new PkixParameters(trustAnchors)
            {
                IsRevocationEnabled = false,
                Date = validationInstant,
            };

            PkixCertPathValidatorResult result =
                new PkixCertPathValidator().Validate(new PkixCertPath(chain), parameters);

            return ChainValidationResult.Success(chain, result.TrustAnchor.TrustedCert);
        }
        catch (PkixCertPathValidatorException)
        {
            // PKIX reports "no anchor terminates this chain" and "this chain does not hold
            // together" through one exception type. They are different faults -- one says a
            // device presented a chain we never agreed to trust, the other says the chain
            // itself is broken -- so they are told apart here rather than collapsed. The
            // decision is made only after PKIX has already refused: a chain that validates
            // is never reclassified by the name comparison below.
            return ChainValidationResult.Failure(ClassifyRejection(chain, anchors));
        }
        catch (Exception error) when (error is CertificateException
                                           or ArgumentException
                                           or InvalidOperationException
                                           or IOException
                                           or FormatException)
        {
            // The families BouncyCastle raises on structurally bad material. This does not
            // catch every exception: a NullReferenceException here would be our defect, and
            // swallowing it would hide it behind a plausible-looking rejection.
            return ChainValidationResult.Failure(AttestationFailureReason.CertificateChainInvalid);
        }
    }

    /// <summary>
    /// Decodes one DER certificate, answering <see langword="null"/> for anything that is
    /// not one.
    /// </summary>
    /// <remarks>
    /// Measured: the parser rejects malformed input in two different ways. It returns null
    /// when the bytes are not a DER sequence at all -- empty input, or plain text -- and it
    /// throws when they are a sequence it cannot decode. Handling only the throw would let
    /// a null travel on and surface later as a <see cref="NullReferenceException"/>, which
    /// is an exception escaping to the caller rather than a reason returned to it.
    /// </remarks>
    private static X509Certificate? TryReadCertificate(byte[] der)
    {
        if (der is null || der.Length == 0)
        {
            return null;
        }

        try
        {
            return new X509CertificateParser().ReadCertificate(der);
        }
        catch (Exception error) when (error is CertificateException
                                           or IOException
                                           or InvalidOperationException
                                           or ArgumentException
                                           or FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Finds the instant to validate at, or reports that no instant would do.
    /// </summary>
    /// <param name="chain">The decoded chain.</param>
    /// <param name="instant">The instant PKIX should validate at.</param>
    /// <returns>
    /// <see langword="false"/> when the chain is outside its validity window by more than
    /// the configured tolerance, or when no single instant exists at which every
    /// certificate in it is valid.
    /// </returns>
    /// <remarks>
    /// <para>
    /// PKIX validates at one instant, so tolerance cannot be expressed by passing it a
    /// wider window. Instead the chain's own window is intersected -- the latest
    /// <c>notBefore</c> against the earliest <c>notAfter</c> -- and the clock is allowed to
    /// sit up to the tolerance outside it. When it does, the instant handed to PKIX is the
    /// nearest edge of that window rather than the reading of our clock.
    /// </para>
    /// <para>
    /// With a zero tolerance this is exactly what PKIX would decide on its own; the check
    /// is here so the answer comes back as <see cref="AttestationFailureReason.CertificateExpired"/>
    /// instead of the one exception PKIX uses for every kind of path failure.
    /// </para>
    /// <para>
    /// The trust anchor's own dates are not part of the intersection. PKIX validates the
    /// path below the anchor, and which roots stay trusted is the caller's decision, not a
    /// date this library second-guesses.
    /// </para>
    /// </remarks>
    private bool TryResolveValidationInstant(IReadOnlyList<X509Certificate> chain, out DateTime instant)
    {
        instant = default;

        DateTime windowStart = DateTime.MinValue;
        DateTime windowEnd = DateTime.MaxValue;

        foreach (X509Certificate certificate in chain)
        {
            // Measured: BouncyCastle returns both bounds with DateTimeKind.Utc, so they
            // compare against a UTC clock as they stand. Converting here would be the
            // dangerous half-step -- ToUniversalTime on an already-UTC or unspecified value
            // shifts it by the machine's offset and the comparison stays silently wrong.
            if (certificate.NotBefore > windowStart)
            {
                windowStart = certificate.NotBefore;
            }

            if (certificate.NotAfter < windowEnd)
            {
                windowEnd = certificate.NotAfter;
            }
        }

        if (windowStart > windowEnd)
        {
            return false;
        }

        DateTime now = _timeProvider.GetUtcNow().UtcDateTime;

        if (now < Shift(windowStart, -_clockSkew) || now > Shift(windowEnd, _clockSkew))
        {
            return false;
        }

        instant = now < windowStart ? windowStart
            : now > windowEnd ? windowEnd
            : now;

        return true;
    }

    /// <summary>
    /// Says whether a refusal was about pinning or about the chain itself.
    /// </summary>
    /// <remarks>
    /// The test is the same subject-to-issuer rule PKIX uses to pick an anchor, and it is
    /// only a name comparison: an anchor that matches by name but did not sign the chain
    /// still leaves the answer at <see cref="AttestationFailureReason.CertificateChainInvalid"/>,
    /// because whether the key signed anything is PKIX's answer and has already been given.
    /// </remarks>
    private static AttestationFailureReason ClassifyRejection(
        IReadOnlyList<X509Certificate> chain,
        IReadOnlyList<X509Certificate> anchors)
    {
        X509Certificate top = chain[chain.Count - 1];

        foreach (X509Certificate anchor in anchors)
        {
            if (anchor.SubjectDN.Equivalent(top.IssuerDN, true))
            {
                return AttestationFailureReason.CertificateChainInvalid;
            }
        }

        return AttestationFailureReason.RootNotPinned;
    }

    /// <summary>Moves an instant by an offset without running off the end of the calendar.</summary>
    /// <param name="value">The instant to move.</param>
    /// <param name="offset">How far to move it.</param>
    /// <returns>The moved instant, saturated at the representable range.</returns>
    private static DateTime Shift(DateTime value, TimeSpan offset)
    {
        if (offset > TimeSpan.Zero && value > DateTime.MaxValue - offset)
        {
            return DateTime.MaxValue;
        }

        if (offset < TimeSpan.Zero && value < DateTime.MinValue - offset)
        {
            return DateTime.MinValue;
        }

        return value + offset;
    }
}
