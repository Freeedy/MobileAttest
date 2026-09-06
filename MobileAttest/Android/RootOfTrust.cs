using System;
using System.Formats.Asn1;

namespace MobileAttest.Android;

/// <summary>
/// What verified boot concluded about the software the device started.
/// </summary>
/// <remarks>
/// A device may report a value this enumeration does not name. The parser preserves the
/// number rather than folding it into a known state, so a caller can tell an unrecognised
/// state from <see cref="Verified"/> with <c>Enum.IsDefined</c>.
/// </remarks>
public enum VerifiedBootState
{
    /// <summary>The boot chain was verified against the device manufacturer's root of trust.</summary>
    Verified = 0,

    /// <summary>The boot chain was verified against a key the device owner installed.</summary>
    SelfSigned = 1,

    /// <summary>The bootloader is unlocked and no verification was performed.</summary>
    Unverified = 2,

    /// <summary>Verification ran and failed.</summary>
    Failed = 3,
}

/// <summary>
/// The verified boot state carried inside an authorisation list.
/// </summary>
/// <remarks>
/// <para>
/// This type only reports what the device said. Whether a given combination is acceptable
/// -- whether an unlocked device may enrol, whether a self-signed boot chain counts -- is a
/// policy decision and is made by the caller, not here.
/// </para>
/// <para>
/// The value is only worth anything when it was read from the hardware-enforced list. The
/// same structure may appear in the software-enforced list, where it is a claim the device
/// software makes about itself; <see cref="AuthorizationList.Source"/> is what keeps the two
/// apart after parsing.
/// </para>
/// </remarks>
public sealed class RootOfTrust
{
    private RootOfTrust(
        ReadOnlyMemory<byte> verifiedBootKey,
        bool deviceLocked,
        VerifiedBootState verifiedBootState,
        ReadOnlyMemory<byte> verifiedBootHash,
        bool hasVerifiedBootHash)
    {
        VerifiedBootKey = verifiedBootKey;
        DeviceLocked = deviceLocked;
        VerifiedBootState = verifiedBootState;
        VerifiedBootHash = verifiedBootHash;
        HasVerifiedBootHash = hasVerifiedBootHash;
    }

    /// <summary>The digest of the key the boot chain was verified against.</summary>
    public ReadOnlyMemory<byte> VerifiedBootKey { get; }

    /// <summary>Whether the device reports its bootloader as locked.</summary>
    public bool DeviceLocked { get; }

    /// <summary>What verified boot concluded.</summary>
    public VerifiedBootState VerifiedBootState { get; }

    /// <summary>
    /// The digest of the verified boot state, or empty when the device did not send one.
    /// Use <see cref="HasVerifiedBootHash"/> to tell absent from empty.
    /// </summary>
    public ReadOnlyMemory<byte> VerifiedBootHash { get; }

    /// <summary>
    /// Whether the device sent a verified boot hash at all. The field is optional in the
    /// schema and older devices omit it, so an absent hash is not a malformed record --
    /// but it is also not a hash of nothing, and a caller must not read it as one.
    /// </summary>
    public bool HasVerifiedBootHash { get; }

    /// <summary>
    /// Reads a RootOfTrust from the contents of its SEQUENCE.
    /// </summary>
    /// <param name="reader">A reader over the SEQUENCE contents.</param>
    /// <param name="result">The parsed value, or null when the contents were rejected.</param>
    /// <returns>Whether the contents matched the structure.</returns>
    /// <remarks>
    /// <para>
    /// The BOOLEAN is read under DER rules, where the only encodings of true and false are
    /// <c>0xFF</c> and <c>0x00</c>. That matters more than it looks: under BER any non-zero
    /// byte is true, so a device sending <c>0x01</c> for <c>deviceLocked</c> would be read
    /// as locked by a lenient parser while presenting an encoding no genuine device
    /// produces. Rejecting it is the difference between reading a claim and accepting one.
    /// </para>
    /// <para>
    /// May throw <see cref="AsnContentException"/>. It is caught at the public boundary in
    /// <see cref="KeyDescription.TryParse(ReadOnlySpan{byte}, out KeyDescription?)"/>, which
    /// is the only way into this parser from outside the library.
    /// </para>
    /// </remarks>
    internal static bool TryParse(AsnReader reader, out RootOfTrust? result)
    {
        result = null;

        byte[] verifiedBootKey = reader.ReadOctetString();
        bool deviceLocked = reader.ReadBoolean();

        // An unrecognised state is read as the number the device sent rather than mapped
        // onto a known state. Folding an unknown value into Verified would be the worst
        // possible default; folding it into Failed would reject devices for using a state
        // this library has not heard of yet. The caller decides, and can see the number.
        VerifiedBootState verifiedBootState = reader.ReadEnumeratedValue<VerifiedBootState>();

        ReadOnlyMemory<byte> verifiedBootHash = ReadOnlyMemory<byte>.Empty;
        bool hasVerifiedBootHash = false;

        if (reader.HasData)
        {
            verifiedBootHash = reader.ReadOctetString();
            hasVerifiedBootHash = true;
        }

        reader.ThrowIfNotEmpty();

        result = new RootOfTrust(
            verifiedBootKey,
            deviceLocked,
            verifiedBootState,
            verifiedBootHash,
            hasVerifiedBootHash);
        return true;
    }
}
