using System;

namespace MobileAttest.Abstractions;

/// <summary>
/// The outcome of verifying an assertion -- the per-request proof that a previously
/// attested key signed this request.
/// </summary>
/// <remarks>
/// Assertion has a different input and a different outcome from attestation, so it does
/// not share <see cref="AttestationResult"/>: the only thing a caller carries forward is
/// the new signature counter.
/// </remarks>
public sealed class AssertionResult
{
    private AssertionResult(bool isValid, AttestationFailureReason reason, uint newSignCount)
    {
        IsValid = isValid;
        Reason = reason;
        NewSignCount = newSignCount;
    }

    /// <summary>Whether every verification step passed.</summary>
    public bool IsValid { get; }

    /// <summary>
    /// Why verification failed. <see cref="AttestationFailureReason.None"/> when
    /// <see cref="IsValid"/> is <see langword="true"/>.
    /// </summary>
    public AttestationFailureReason Reason { get; }

    /// <summary>
    /// The signature counter the caller must store in place of the previous one. Only
    /// meaningful when <see cref="IsValid"/> is <see langword="true"/>.
    /// </summary>
    public uint NewSignCount { get; }

    /// <summary>Creates a successful result.</summary>
    /// <param name="newSignCount">The counter the caller must persist for the next request.</param>
    /// <returns>A result whose <see cref="IsValid"/> is <see langword="true"/>.</returns>
    public static AssertionResult Success(uint newSignCount) =>
        new AssertionResult(isValid: true, reason: AttestationFailureReason.None, newSignCount: newSignCount);

    /// <summary>Creates a failed result.</summary>
    /// <param name="reason">Why verification failed.</param>
    /// <returns>A result whose <see cref="IsValid"/> is <see langword="false"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="reason"/> is <see cref="AttestationFailureReason.None"/>, which would
    /// describe a failure with no cause.
    /// </exception>
    public static AssertionResult Failure(AttestationFailureReason reason)
    {
        if (reason == AttestationFailureReason.None)
        {
            throw new ArgumentOutOfRangeException(
                nameof(reason),
                "A failed result must name a reason.");
        }

        return new AssertionResult(isValid: false, reason: reason, newSignCount: 0);
    }
}
