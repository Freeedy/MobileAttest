using System;

namespace MobileAttest.Trust;

/// <summary>
/// The limits a chain validation runs under. These are bounds on attacker-supplied input,
/// not policy about which roots to trust: roots always arrive separately, from the caller.
/// </summary>
public sealed class ChainValidationPolicy
{
    /// <summary>The default ceiling on how many certificates a chain may carry.</summary>
    /// <remarks>
    /// Real attestation chains are three or four certificates. Ten leaves room for a
    /// platform to add a tier without leaving the number so large that a sender can spend
    /// our time by padding its chain.
    /// </remarks>
    public const int DefaultMaxChainLength = 10;

    /// <summary>The default tolerance for disagreement between our clock and the issuer's.</summary>
    public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromMinutes(5);

    /// <summary>
    /// How many certificates a chain may carry before it is rejected. The count is checked
    /// before any certificate is decoded, so a long chain costs a comparison rather than a
    /// parse.
    /// </summary>
    public int MaxChainLength { get; set; } = DefaultMaxChainLength;

    /// <summary>
    /// How far our clock may be out before validity dates are treated as wrong.
    /// </summary>
    /// <remarks>
    /// A certificate is accepted when it is valid at some instant within this distance of
    /// now. The tolerance widens the window at both ends, so it is a loosening: a value
    /// long enough to cover a certificate's whole lifetime stops expiry from being
    /// checked at all. Keep it at the scale of clock drift, not of certificate lifetime.
    /// </remarks>
    public TimeSpan ClockSkew { get; set; } = DefaultClockSkew;

    /// <summary>
    /// Rejects a configuration that could not be applied as written.
    /// </summary>
    /// <exception cref="InvalidOperationException">The configuration is out of range.</exception>
    public void Validate()
    {
        if (MaxChainLength < 1)
        {
            throw new InvalidOperationException(
                $"{nameof(ChainValidationPolicy)}.{nameof(MaxChainLength)} must be at least 1; " +
                "a chain with no certificates cannot be validated against anything.");
        }

        if (ClockSkew < TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"{nameof(ChainValidationPolicy)}.{nameof(ClockSkew)} must not be negative; " +
                "tolerance widens the validity window and cannot narrow it.");
        }
    }
}
