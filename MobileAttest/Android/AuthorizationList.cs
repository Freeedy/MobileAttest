using System;
using System.Collections.Generic;
using System.Formats.Asn1;

namespace MobileAttest.Android;

/// <summary>
/// Which of a KeyDescription's two authorisation lists a value was read from.
/// </summary>
/// <remarks>
/// <para>
/// A KeyDescription carries the same shape of list twice, and the two carry entirely
/// different weight. The hardware-enforced list is what the secure element vouches for.
/// The software-enforced list is assembled by the Android framework, which is the part of
/// the device an attacker who has rooted it controls.
/// </para>
/// <para>
/// The lists are therefore never merged, and a list that has been handed to a caller still
/// says where it came from. Losing that distinction is the whole attack: a device that can
/// have a software-enforced field read as a hardware-enforced one can say whatever it likes
/// about itself.
/// </para>
/// </remarks>
public enum AuthorizationListSource
{
    /// <summary>
    /// The list the Android framework assembled. Its contents are claims the device
    /// software makes, not claims the secure hardware attests to.
    /// </summary>
    SoftwareEnforced = 0,

    /// <summary>
    /// The list the secure hardware enforced. This is the one a security decision may rest
    /// on.
    /// </summary>
    HardwareEnforced = 1,
}

/// <summary>
/// Where the key material came from.
/// </summary>
/// <remarks>
/// A device may report a value this enumeration does not name; the number is preserved
/// rather than folded into a known origin.
/// </remarks>
public enum KeyOrigin
{
    /// <summary>The key was generated inside the secure hardware.</summary>
    Generated = 0,

    /// <summary>The key was derived inside the secure hardware.</summary>
    Derived = 1,

    /// <summary>The key was imported, so the hardware never had exclusive custody of it.</summary>
    Imported = 2,

    /// <summary>The origin is not known, which for a security decision is the same as imported.</summary>
    Unknown = 3,
}

/// <summary>
/// One of the two authorisation lists inside a KeyDescription.
/// </summary>
/// <remarks>
/// <para>
/// Fields are optional and identified by context-specific tag, not by position, so a list
/// is read as a tag-driven loop rather than as a fixed sequence. Every field is exposed as
/// nullable or as a possibly-empty collection: an absent field is absent, and is not
/// reported as a zero.
/// </para>
/// <para><b>An unrecognised tag is not an error.</b></para>
/// <para>
/// Android adds tags with new releases. A parser that rejected an unknown tag would work
/// until the next Android version and then reject every device carrying it, which is a
/// worse failure than not understanding one field. Unknown tags are skipped and recorded on
/// <see cref="UnknownTags"/>, so "skipped" can be told apart from "silently dropped".
/// </para>
/// <para>
/// A structural violation is a different matter and is rejected: a tag outside the
/// context-specific class, a known tag carrying the wrong type, a known tag appearing
/// twice. The last one is worth naming -- without that check a device could append a second
/// rootOfTrust and let the later value quietly replace the earlier one.
/// </para>
/// </remarks>
public sealed class AuthorizationList
{
    private const int PurposeTag = 1;
    private const int AlgorithmTag = 2;
    private const int KeySizeTag = 3;
    private const int DigestTag = 5;
    private const int EcCurveTag = 10;
    private const int NoAuthRequiredTag = 503;
    private const int CreationDateTimeTag = 701;
    private const int OriginTag = 702;
    private const int RootOfTrustTag = 704;
    private const int OsVersionTag = 705;
    private const int OsPatchLevelTag = 706;
    private const int AttestationApplicationIdTag = 709;
    private const int VendorPatchLevelTag = 718;
    private const int BootPatchLevelTag = 719;

    private static readonly HashSet<int> KnownTags = new HashSet<int>
    {
        PurposeTag,
        AlgorithmTag,
        KeySizeTag,
        DigestTag,
        EcCurveTag,
        NoAuthRequiredTag,
        CreationDateTimeTag,
        OriginTag,
        RootOfTrustTag,
        OsVersionTag,
        OsPatchLevelTag,
        AttestationApplicationIdTag,
        VendorPatchLevelTag,
        BootPatchLevelTag,
    };

    private AuthorizationList(
        AuthorizationListSource source,
        IReadOnlyList<int> purpose,
        long? algorithm,
        long? keySize,
        IReadOnlyList<int> digest,
        long? ecCurve,
        bool noAuthRequired,
        long? creationDateTime,
        KeyOrigin? origin,
        RootOfTrust? rootOfTrust,
        long? osVersion,
        long? osPatchLevel,
        AttestationApplicationId? attestationApplicationId,
        long? vendorPatchLevel,
        long? bootPatchLevel,
        IReadOnlyList<int> unknownTags)
    {
        Source = source;
        Purpose = purpose;
        Algorithm = algorithm;
        KeySize = keySize;
        Digest = digest;
        EcCurve = ecCurve;
        NoAuthRequired = noAuthRequired;
        CreationDateTime = creationDateTime;
        Origin = origin;
        RootOfTrust = rootOfTrust;
        OsVersion = osVersion;
        OsPatchLevel = osPatchLevel;
        AttestationApplicationId = attestationApplicationId;
        VendorPatchLevel = vendorPatchLevel;
        BootPatchLevel = bootPatchLevel;
        UnknownTags = unknownTags;
    }

    /// <summary>
    /// Which list this is. It travels with the value so that a caller holding a list on its
    /// own still knows how much the list is worth.
    /// </summary>
    public AuthorizationListSource Source { get; }

    /// <summary>The operations the key may be used for, empty when the field is absent.</summary>
    public IReadOnlyList<int> Purpose { get; }

    /// <summary>The key algorithm, or null when the field is absent.</summary>
    public long? Algorithm { get; }

    /// <summary>The key size in bits, or null when the field is absent.</summary>
    public long? KeySize { get; }

    /// <summary>The digests the key may be used with, empty when the field is absent.</summary>
    public IReadOnlyList<int> Digest { get; }

    /// <summary>The elliptic curve identifier, or null when the field is absent.</summary>
    public long? EcCurve { get; }

    /// <summary>Whether the key may be used without user authentication.</summary>
    public bool NoAuthRequired { get; }

    /// <summary>
    /// When the key was created, in milliseconds since the Unix epoch, or null when the
    /// field is absent. The device supplies this clock, so it is a claim, not a timestamp.
    /// </summary>
    public long? CreationDateTime { get; }

    /// <summary>Where the key material came from, or null when the field is absent.</summary>
    public KeyOrigin? Origin { get; }

    /// <summary>The verified boot state, or null when the field is absent.</summary>
    public RootOfTrust? RootOfTrust { get; }

    /// <summary>The operating system version, or null when the field is absent.</summary>
    public long? OsVersion { get; }

    /// <summary>The operating system patch level, or null when the field is absent.</summary>
    public long? OsPatchLevel { get; }

    /// <summary>
    /// The application identity the key is bound to, or null when the field is absent.
    /// </summary>
    /// <remarks>
    /// Measured on a real device, this field is present in the software-enforced list and
    /// absent from the hardware-enforced one. It is reached through a list, and only
    /// through a list, so that reading it always means having decided which list to trust
    /// it from.
    /// </remarks>
    public AttestationApplicationId? AttestationApplicationId { get; }

    /// <summary>The vendor image patch level, or null when the field is absent.</summary>
    public long? VendorPatchLevel { get; }

    /// <summary>The boot image patch level, or null when the field is absent.</summary>
    public long? BootPatchLevel { get; }

    /// <summary>
    /// The context-specific tag numbers that were present and not understood, in the order
    /// they appeared.
    /// </summary>
    /// <remarks>
    /// Skipping an unknown tag is what keeps this library working across Android releases.
    /// Recording it is what keeps the skip honest: without this list, a field the device
    /// sent and the library ignored would leave no trace anywhere.
    /// </remarks>
    public IReadOnlyList<int> UnknownTags { get; }

    /// <summary>
    /// Reads an authorisation list from the contents of its SEQUENCE.
    /// </summary>
    /// <param name="reader">A reader over the SEQUENCE contents.</param>
    /// <param name="source">Which of the two lists this is.</param>
    /// <param name="result">The parsed list, or null when the contents were rejected.</param>
    /// <returns>Whether the contents matched the structure.</returns>
    /// <remarks>
    /// May throw <see cref="AsnContentException"/>; see
    /// <see cref="KeyDescription.TryParse(ReadOnlySpan{byte}, out KeyDescription?)"/> for
    /// where that is caught.
    /// </remarks>
    internal static bool TryParse(
        AsnReader reader,
        AuthorizationListSource source,
        out AuthorizationList? result)
    {
        result = null;

        List<int> purpose = new List<int>();
        long? algorithm = null;
        long? keySize = null;
        List<int> digest = new List<int>();
        long? ecCurve = null;
        bool noAuthRequired = false;
        long? creationDateTime = null;
        KeyOrigin? origin = null;
        RootOfTrust? rootOfTrust = null;
        long? osVersion = null;
        long? osPatchLevel = null;
        AttestationApplicationId? attestationApplicationId = null;
        long? vendorPatchLevel = null;
        long? bootPatchLevel = null;

        HashSet<int> seenTags = new HashSet<int>();
        List<int> unknownTags = new List<int>();

        while (reader.HasData)
        {
            Asn1Tag peeked = reader.PeekTag();

            // Every field of an authorisation list is context-specific. A universal or
            // application tag here is not a field this library has yet to learn about, it
            // is a structure that does not match the schema.
            if (peeked.TagClass != TagClass.ContextSpecific)
            {
                return false;
            }

            int tagNumber = peeked.TagValue;

            if (!KnownTags.Contains(tagNumber))
            {
                unknownTags.Add(tagNumber);
                reader.ReadEncodedValue();
                continue;
            }

            if (!seenTags.Add(tagNumber))
            {
                return false;
            }

            // The schema tags explicitly, so each field is a constructed wrapper around the
            // value. Asking for the constructed form by name is what rejects a primitive
            // tag pretending to be one of these fields.
            Asn1Tag expected = new Asn1Tag(TagClass.ContextSpecific, tagNumber, isConstructed: true);
            AsnReader field = reader.ReadSequence(expected);

            switch (tagNumber)
            {
                case PurposeTag:
                    if (!TryReadIntegerSet(field, purpose))
                    {
                        return false;
                    }

                    break;

                case AlgorithmTag:
                    if (!field.TryReadInt64(out long algorithmValue))
                    {
                        return false;
                    }

                    algorithm = algorithmValue;
                    break;

                case KeySizeTag:
                    if (!field.TryReadInt64(out long keySizeValue))
                    {
                        return false;
                    }

                    keySize = keySizeValue;
                    break;

                case DigestTag:
                    if (!TryReadIntegerSet(field, digest))
                    {
                        return false;
                    }

                    break;

                case EcCurveTag:
                    if (!field.TryReadInt64(out long ecCurveValue))
                    {
                        return false;
                    }

                    ecCurve = ecCurveValue;
                    break;

                case NoAuthRequiredTag:
                    field.ReadNull();
                    noAuthRequired = true;
                    break;

                case CreationDateTimeTag:
                    if (!field.TryReadInt64(out long creationValue))
                    {
                        return false;
                    }

                    creationDateTime = creationValue;
                    break;

                case OriginTag:
                    if (!field.TryReadInt32(out int originValue))
                    {
                        return false;
                    }

                    origin = (KeyOrigin)originValue;
                    break;

                case RootOfTrustTag:
                {
                    AsnReader rootBody = field.ReadSequence();

                    if (!MobileAttest.Android.RootOfTrust.TryParse(rootBody, out RootOfTrust? parsedRoot))
                    {
                        return false;
                    }

                    rootOfTrust = parsedRoot;
                    break;
                }

                case OsVersionTag:
                    if (!field.TryReadInt64(out long osVersionValue))
                    {
                        return false;
                    }

                    osVersion = osVersionValue;
                    break;

                case OsPatchLevelTag:
                    if (!field.TryReadInt64(out long osPatchValue))
                    {
                        return false;
                    }

                    osPatchLevel = osPatchValue;
                    break;

                case AttestationApplicationIdTag:
                {
                    byte[] nested = field.ReadOctetString();

                    if (!MobileAttest.Android.AttestationApplicationId.TryParse(
                            nested,
                            out AttestationApplicationId? parsedAppId))
                    {
                        return false;
                    }

                    attestationApplicationId = parsedAppId;
                    break;
                }

                case VendorPatchLevelTag:
                    if (!field.TryReadInt64(out long vendorPatchValue))
                    {
                        return false;
                    }

                    vendorPatchLevel = vendorPatchValue;
                    break;

                case BootPatchLevelTag:
                    if (!field.TryReadInt64(out long bootPatchValue))
                    {
                        return false;
                    }

                    bootPatchLevel = bootPatchValue;
                    break;

                default:
                    // KnownTags and this switch are the same list written twice; a tag in
                    // one and not the other is a mistake in this file, not bad input.
                    return false;
            }

            field.ThrowIfNotEmpty();
        }

        result = new AuthorizationList(
            source,
            purpose,
            algorithm,
            keySize,
            digest,
            ecCurve,
            noAuthRequired,
            creationDateTime,
            origin,
            rootOfTrust,
            osVersion,
            osPatchLevel,
            attestationApplicationId,
            vendorPatchLevel,
            bootPatchLevel,
            unknownTags);
        return true;
    }

    private static bool TryReadIntegerSet(AsnReader field, List<int> destination)
    {
        // See AttestationApplicationId for why element order inside a SET OF is not
        // validated: every element is read, so the order means nothing here.
        AsnReader set = field.ReadSetOf(skipSortOrderValidation: true);

        while (set.HasData)
        {
            if (!set.TryReadInt32(out int value))
            {
                return false;
            }

            destination.Add(value);
        }

        return true;
    }
}
