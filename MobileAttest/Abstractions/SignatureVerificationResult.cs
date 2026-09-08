using System;

namespace MobileAttest.Abstractions;

/// <summary>
/// The outcome of checking one signature against one stored public key.
/// </summary>
/// <remarks>
/// <para>
/// This is the narrowest result type in the library, and deliberately so. It answers one
/// question -- did this key produce this signature over these bytes -- and says nothing
/// about what the bytes meant. What the signed message stands for, whether it was fresh,
/// and whether it belonged to the operation being performed are all the caller's to decide;
/// see <see cref="MobileAttest.Protocol.DeviceSignature"/> for why.
/// </para>
/// </remarks>
public sealed class SignatureVerificationResult
{
    private SignatureVerificationResult(bool isValid, AttestationFailureReason reason)
    {
        IsValid = isValid;
        Reason = reason;
    }

    /// <summary>Whether the signature verified.</summary>
    public bool IsValid { get; }

    /// <summary>Why it did not, or <see cref="AttestationFailureReason.None"/> when it did.</summary>
    public AttestationFailureReason Reason { get; }

    /// <summary>The signature verified against the supplied key.</summary>
    /// <returns>A successful result.</returns>
    public static SignatureVerificationResult Success() =>
        new SignatureVerificationResult(isValid: true, reason: AttestationFailureReason.None);

    /// <summary>The signature did not verify.</summary>
    /// <param name="reason">Why not. Must not be <see cref="AttestationFailureReason.None"/>.</param>
    /// <returns>A failed result carrying the reason.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The reason is <see cref="AttestationFailureReason.None"/>.</exception>
    public static SignatureVerificationResult Failure(AttestationFailureReason reason)
    {
        if (reason == AttestationFailureReason.None)
        {
            throw new ArgumentOutOfRangeException(
                nameof(reason),
                "A failed result must name a reason.");
        }

        return new SignatureVerificationResult(isValid: false, reason: reason);
    }
}
