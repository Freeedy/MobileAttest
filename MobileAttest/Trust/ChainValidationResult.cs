using System;
using System.Collections.Generic;
using MobileAttest.Abstractions;
using Org.BouncyCastle.X509;

namespace MobileAttest.Trust;

/// <summary>
/// The answer to one question: does this certificate chain reach a root the caller pinned,
/// with every certificate inside its validity window?
/// </summary>
/// <remarks>
/// A failure carries a reason from the shared enum and nothing else. The underlying PKIX
/// exception text names internal structure and is never propagated to the caller; detail
/// belongs in the server's log, not in a response a client can read.
/// </remarks>
public sealed class ChainValidationResult
{
    private static readonly IReadOnlyList<X509Certificate> NoPath = Array.Empty<X509Certificate>();

    private ChainValidationResult(
        bool isValid,
        AttestationFailureReason reason,
        IReadOnlyList<X509Certificate> validatedPath,
        X509Certificate? trustAnchor)
    {
        IsValid = isValid;
        Reason = reason;
        ValidatedPath = validatedPath;
        TrustAnchor = trustAnchor;
    }

    /// <summary>Whether the chain validated.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Why the chain was rejected, or <see cref="AttestationFailureReason.None"/> when it
    /// was not.
    /// </summary>
    public AttestationFailureReason Reason { get; }

    /// <summary>
    /// The decoded chain, leaf first, on success; empty on failure.
    /// </summary>
    /// <remarks>
    /// Returned so that a caller reading the leaf -- for a key attestation extension, or
    /// for the attested public key -- works from the certificates this validator actually
    /// verified, rather than decoding the same bytes a second time and risking a
    /// disagreement between the two decodes.
    /// </remarks>
    public IReadOnlyList<X509Certificate> ValidatedPath { get; }

    /// <summary>
    /// The pinned root the chain terminated in, on success; <see langword="null"/> on
    /// failure.
    /// </summary>
    public X509Certificate? TrustAnchor { get; }

    /// <summary>Records a chain that validated to a pinned root.</summary>
    /// <param name="validatedPath">The decoded chain, leaf first.</param>
    /// <param name="trustAnchor">The pinned root it terminated in.</param>
    /// <returns>A successful result.</returns>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="validatedPath"/> is empty.</exception>
    public static ChainValidationResult Success(
        IReadOnlyList<X509Certificate> validatedPath,
        X509Certificate trustAnchor)
    {
        if (validatedPath is null)
        {
            throw new ArgumentNullException(nameof(validatedPath));
        }

        if (trustAnchor is null)
        {
            throw new ArgumentNullException(nameof(trustAnchor));
        }

        if (validatedPath.Count == 0)
        {
            throw new ArgumentException(
                "A successful result must name the chain that was validated.",
                nameof(validatedPath));
        }

        return new ChainValidationResult(true, AttestationFailureReason.None, validatedPath, trustAnchor);
    }

    /// <summary>Records a rejected chain.</summary>
    /// <param name="reason">Why it was rejected.</param>
    /// <returns>A failed result.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="reason"/> is <see cref="AttestationFailureReason.None"/>. A failure
    /// that reports no reason reads as a success everywhere it is logged or compared,
    /// which is the silent pass this library exists to avoid.
    /// </exception>
    public static ChainValidationResult Failure(AttestationFailureReason reason)
    {
        if (reason == AttestationFailureReason.None)
        {
            throw new ArgumentOutOfRangeException(
                nameof(reason),
                reason,
                "A rejected chain must name a reason.");
        }

        return new ChainValidationResult(false, reason, NoPath, null);
    }
}
