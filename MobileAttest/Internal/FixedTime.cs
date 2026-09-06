using Org.BouncyCastle.Utilities;

namespace MobileAttest.Internal;

/// <summary>
/// Comparisons whose running time does not depend on where two inputs first differ.
/// </summary>
/// <remarks>
/// Every equality check on attacker-influenced material -- nonces, digests, key
/// identifiers, signature counters read from a device -- goes through here. A plain
/// <c>SequenceEqual</c> returns as soon as it finds a difference, which leaks the
/// position of that difference through timing.
/// </remarks>
internal static class FixedTime
{
    /// <summary>
    /// Compares two byte sequences without an early exit on the first differing byte.
    /// </summary>
    /// <param name="left">The first sequence, or <see langword="null"/>.</param>
    /// <param name="right">The second sequence, or <see langword="null"/>.</param>
    /// <returns>
    /// <see langword="true"/> only when both sequences are present, of equal length, and
    /// equal byte for byte. A length mismatch or a null operand yields
    /// <see langword="false"/> rather than an exception, so a caller never has to branch
    /// on malformed input before comparing.
    /// </returns>
    /// <remarks>
    /// Backed by <c>Arrays.FixedTimeEquals</c>. Its older name
    /// <c>Arrays.ConstantTimeAreEqual</c> still exists in the referenced package but is
    /// marked obsolete there; the dependency smoke test pins both facts.
    /// </remarks>
    internal static bool FixedTimeEquals(byte[]? left, byte[]? right)
    {
        if (left is null || right is null)
        {
            return false;
        }

        return Arrays.FixedTimeEquals(left, right);
    }
}
