using System.Formats.Asn1;
using System.Numerics;

namespace MobileAttest.Android;

/// <summary>
/// DER integer reading shared by the Android key attestation parsers.
/// </summary>
/// <remarks>
/// <para>
/// Every integer in a KeyDescription arrives from the device, so its magnitude is
/// attacker-controlled. <see cref="AsnReader.ReadInteger"/> returns a
/// <see cref="BigInteger"/>, which never overflows but also never says "this does not
/// belong here"; the range check has to be written somewhere.
/// </para>
/// <para>
/// It is written once, here, rather than at each of the dozen or so call sites in
/// <see cref="AuthorizationList"/>, <see cref="KeyDescription"/> and
/// <see cref="AttestationApplicationId"/>. A bounds check copied twelve times is a bounds
/// check that will eventually be copied eleven times.
/// </para>
/// <para>
/// Enumerated values do not come through here. They share the content rules of an integer
/// but not its tag, and <see cref="AsnReader.ReadInteger"/> refuses a universal tag that
/// is not INTEGER, so they are read with <c>ReadEnumeratedValue</c> at their call sites.
/// </para>
/// </remarks>
internal static class AsnReaderExtensions
{
    /// <summary>
    /// Reads an INTEGER and reports whether it fits in 64 bits.
    /// </summary>
    /// <param name="reader">The reader positioned on the value.</param>
    /// <param name="value">The value, or zero when it did not fit.</param>
    /// <returns>
    /// <see langword="true"/> when the value was read and fits; otherwise
    /// <see langword="false"/>. The reader has advanced past the value either way.
    /// </returns>
    internal static bool TryReadInt64(this AsnReader reader, out long value)
    {
        BigInteger raw = reader.ReadInteger();

        if (raw < long.MinValue || raw > long.MaxValue)
        {
            value = 0;
            return false;
        }

        value = (long)raw;
        return true;
    }

    /// <summary>
    /// Reads an INTEGER and reports whether it fits in 32 bits.
    /// </summary>
    /// <param name="reader">The reader positioned on the value.</param>
    /// <param name="value">The value, or zero when it did not fit.</param>
    /// <returns>
    /// <see langword="true"/> when the value was read and fits; otherwise
    /// <see langword="false"/>. The reader has advanced past the value either way.
    /// </returns>
    internal static bool TryReadInt32(this AsnReader reader, out int value)
    {
        if (!reader.TryReadInt64(out long wide) ||
            wide < int.MinValue ||
            wide > int.MaxValue)
        {
            value = 0;
            return false;
        }

        value = (int)wide;
        return true;
    }
}
