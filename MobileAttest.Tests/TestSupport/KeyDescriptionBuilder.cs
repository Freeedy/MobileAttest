namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// A minimal DER encoder, written by hand so that the tests can produce encodings a
/// well-behaved writer refuses to produce.
/// </summary>
/// <remarks>
/// <para>
/// Using <c>AsnWriter</c> here would be circular in two ways. It cannot emit the inputs
/// half of these tests exist for -- a length that overstates its buffer, a tag in the wrong
/// class -- because it is built to prevent exactly those. And it comes from the same
/// library the parser reads with, so a shared misunderstanding of the encoding would cancel
/// out and the tests would agree with the parser about something untrue.
/// </para>
/// <para>
/// The encoder is checked against <c>openssl asn1parse</c> rather than against the parser
/// it feeds, which is what makes it an independent oracle rather than a mirror.
/// </para>
/// </remarks>
internal static class Der
{
    internal const byte BooleanTag = 0x01;
    internal const byte IntegerTag = 0x02;
    internal const byte OctetStringTag = 0x04;
    internal const byte NullTag = 0x05;
    internal const byte EnumeratedTag = 0x0A;
    internal const byte SequenceTag = 0x30;
    internal const byte SetTag = 0x31;

    /// <summary>Joins encoded values in order.</summary>
    internal static byte[] Concat(params byte[][] parts)
    {
        List<byte> buffer = new List<byte>();

        foreach (byte[] part in parts)
        {
            buffer.AddRange(part);
        }

        return buffer.ToArray();
    }

    /// <summary>Encodes one value with a single-byte tag.</summary>
    internal static byte[] Encode(byte tag, byte[] content) =>
        Concat(new[] { tag }, LengthBytes(content.Length), content);

    /// <summary>
    /// Encodes one value whose declared length is not the length of its content. This is
    /// the shape of a device that lies about how much data it is sending.
    /// </summary>
    internal static byte[] EncodeWithDeclaredLength(byte tag, int declaredLength, byte[] content) =>
        Concat(new[] { tag }, LengthBytes(declaredLength), content);

    /// <summary>
    /// Encodes an explicitly tagged, context-specific field: the constructed wrapper the
    /// Android schema puts around every authorisation list entry.
    /// </summary>
    internal static byte[] ContextSpecific(int tagNumber, byte[] content) =>
        Concat(TagBytes(0x80, tagNumber, constructed: true), LengthBytes(content.Length), content);

    /// <summary>Encodes a non-negative INTEGER.</summary>
    internal static byte[] Integer(long value) => Encode(IntegerTag, IntegerContent(value));

    /// <summary>Encodes a non-negative ENUMERATED, which shares the INTEGER content rules.</summary>
    internal static byte[] Enumerated(long value) => Encode(EnumeratedTag, IntegerContent(value));

    /// <summary>Encodes an OCTET STRING.</summary>
    internal static byte[] OctetString(byte[] value) => Encode(OctetStringTag, value);

    /// <summary>Encodes NULL.</summary>
    internal static byte[] Null() => Encode(NullTag, Array.Empty<byte>());

    /// <summary>
    /// Encodes a BOOLEAN with the exact content byte given, so a test can send the
    /// non-canonical <c>0x01</c> that DER forbids and BER would read as true.
    /// </summary>
    internal static byte[] Boolean(byte contentByte) => Encode(BooleanTag, new[] { contentByte });

    /// <summary>Encodes a SEQUENCE around already-encoded values.</summary>
    internal static byte[] Sequence(params byte[][] elements) => Encode(SequenceTag, Concat(elements));

    /// <summary>Encodes a SET around already-encoded values, in the order given.</summary>
    internal static byte[] Set(params byte[][] elements) => Encode(SetTag, Concat(elements));

    /// <summary>Encodes the length octets, short form where the length allows it.</summary>
    internal static byte[] LengthBytes(int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        if (length < 0x80)
        {
            return new[] { (byte)length };
        }

        List<byte> value = new List<byte>();
        int remaining = length;

        while (remaining > 0)
        {
            value.Insert(0, (byte)(remaining & 0xFF));
            remaining >>= 8;
        }

        List<byte> encoded = new List<byte> { (byte)(0x80 | value.Count) };
        encoded.AddRange(value);
        return encoded.ToArray();
    }

    /// <summary>
    /// Encodes the identifier octets, using the high-tag-number form above 30. Android's
    /// authorisation lists need it: tag 709 is three bytes, not one.
    /// </summary>
    internal static byte[] TagBytes(byte tagClass, int tagNumber, bool constructed)
    {
        if (tagNumber < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(tagNumber));
        }

        byte leading = (byte)(tagClass | (constructed ? 0x20 : 0x00));

        if (tagNumber < 0x1F)
        {
            return new[] { (byte)(leading | tagNumber) };
        }

        List<byte> digits = new List<byte>();
        int remaining = tagNumber;

        while (remaining > 0)
        {
            digits.Insert(0, (byte)(remaining & 0x7F));
            remaining >>= 7;
        }

        for (int i = 0; i < digits.Count - 1; i++)
        {
            digits[i] |= 0x80;
        }

        List<byte> encoded = new List<byte> { (byte)(leading | 0x1F) };
        encoded.AddRange(digits);
        return encoded.ToArray();
    }

    /// <summary>Encodes a non-negative integer as minimal two's complement content.</summary>
    internal static byte[] IntegerContent(long value)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                "Negative values are not produced by any field these tests build.");
        }

        if (value == 0)
        {
            return new byte[] { 0x00 };
        }

        List<byte> bytes = new List<byte>();
        long remaining = value;

        while (remaining > 0)
        {
            bytes.Insert(0, (byte)(remaining & 0xFF));
            remaining >>= 8;
        }

        if ((bytes[0] & 0x80) != 0)
        {
            bytes.Insert(0, 0x00);
        }

        return bytes.ToArray();
    }
}

/// <summary>Builds the RootOfTrust structure, corruptible field by field.</summary>
internal sealed class RootOfTrustBuilder
{
    /// <summary>The verified boot key digest.</summary>
    public byte[] VerifiedBootKey { get; set; } = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    /// <summary>
    /// The raw content byte of the deviceLocked BOOLEAN. DER allows only 0x00 and 0xFF;
    /// this is a byte rather than a bool so a test can send what DER forbids.
    /// </summary>
    public byte DeviceLockedContentByte { get; set; } = 0xFF;

    /// <summary>The verified boot state.</summary>
    public long VerifiedBootState { get; set; }

    /// <summary>The verified boot hash, or null to omit the optional field.</summary>
    public byte[]? VerifiedBootHash { get; set; } =
        Enumerable.Range(0, 32).Select(i => (byte)(0xF0 - i)).ToArray();

    /// <summary>Encodes the SEQUENCE.</summary>
    public byte[] Build()
    {
        List<byte[]> elements = new List<byte[]>
        {
            Der.OctetString(VerifiedBootKey),
            Der.Boolean(DeviceLockedContentByte),
            Der.Enumerated(VerifiedBootState),
        };

        if (VerifiedBootHash is not null)
        {
            elements.Add(Der.OctetString(VerifiedBootHash));
        }

        return Der.Sequence(elements.ToArray());
    }
}

/// <summary>Builds one authorisation list.</summary>
/// <remarks>
/// Every field is optional, which is what the schema says and what lets a test build a
/// software-enforced list that carries the application identity and a hardware-enforced one
/// that does not -- the arrangement measured on a real device.
/// </remarks>
internal sealed class AuthorizationListBuilder
{
    /// <summary>Tag 1, purpose.</summary>
    public List<int> Purpose { get; } = new List<int>();

    /// <summary>Tag 2, algorithm.</summary>
    public long? Algorithm { get; set; }

    /// <summary>Tag 3, key size in bits.</summary>
    public long? KeySize { get; set; }

    /// <summary>Tag 5, digest.</summary>
    public List<int> Digest { get; } = new List<int>();

    /// <summary>Tag 10, elliptic curve.</summary>
    public long? EcCurve { get; set; }

    /// <summary>Tag 503, noAuthRequired.</summary>
    public bool NoAuthRequired { get; set; }

    /// <summary>Tag 701, creationDateTime.</summary>
    public long? CreationDateTime { get; set; }

    /// <summary>Tag 702, origin.</summary>
    public long? Origin { get; set; }

    /// <summary>Tag 704, rootOfTrust.</summary>
    public RootOfTrustBuilder? RootOfTrust { get; set; }

    /// <summary>Tag 705, osVersion.</summary>
    public long? OsVersion { get; set; }

    /// <summary>Tag 706, osPatchLevel.</summary>
    public long? OsPatchLevel { get; set; }

    /// <summary>
    /// Tag 709, attestationApplicationId, as the already-encoded nested document the tag
    /// carries inside an OCTET STRING.
    /// </summary>
    public byte[]? AttestationApplicationId { get; set; }

    /// <summary>Tag 718, vendorPatchLevel.</summary>
    public long? VendorPatchLevel { get; set; }

    /// <summary>Tag 719, bootPatchLevel.</summary>
    public long? BootPatchLevel { get; set; }

    /// <summary>
    /// Already-encoded values written ahead of the named fields, verbatim.
    /// </summary>
    /// <remarks>
    /// They go first so that a test proves more than "the list still parsed": everything
    /// the parser reads afterwards had to survive whatever was put here, which is the
    /// difference between skipping an unrecognised tag and losing the reader's position.
    /// </remarks>
    public List<byte[]> LeadingElements { get; } = new List<byte[]>();

    /// <summary>Encodes the SEQUENCE.</summary>
    public byte[] Build()
    {
        List<byte[]> elements = new List<byte[]>(LeadingElements);

        if (Purpose.Count > 0)
        {
            elements.Add(Der.ContextSpecific(1, Der.Set(Purpose.Select(p => Der.Integer(p)).ToArray())));
        }

        if (Algorithm is long algorithm)
        {
            elements.Add(Der.ContextSpecific(2, Der.Integer(algorithm)));
        }

        if (KeySize is long keySize)
        {
            elements.Add(Der.ContextSpecific(3, Der.Integer(keySize)));
        }

        if (Digest.Count > 0)
        {
            elements.Add(Der.ContextSpecific(5, Der.Set(Digest.Select(d => Der.Integer(d)).ToArray())));
        }

        if (EcCurve is long ecCurve)
        {
            elements.Add(Der.ContextSpecific(10, Der.Integer(ecCurve)));
        }

        if (NoAuthRequired)
        {
            elements.Add(Der.ContextSpecific(503, Der.Null()));
        }

        if (CreationDateTime is long creationDateTime)
        {
            elements.Add(Der.ContextSpecific(701, Der.Integer(creationDateTime)));
        }

        if (Origin is long origin)
        {
            elements.Add(Der.ContextSpecific(702, Der.Integer(origin)));
        }

        if (RootOfTrust is not null)
        {
            elements.Add(Der.ContextSpecific(704, RootOfTrust.Build()));
        }

        if (OsVersion is long osVersion)
        {
            elements.Add(Der.ContextSpecific(705, Der.Integer(osVersion)));
        }

        if (OsPatchLevel is long osPatchLevel)
        {
            elements.Add(Der.ContextSpecific(706, Der.Integer(osPatchLevel)));
        }

        if (AttestationApplicationId is not null)
        {
            elements.Add(Der.ContextSpecific(709, Der.OctetString(AttestationApplicationId)));
        }

        if (VendorPatchLevel is long vendorPatchLevel)
        {
            elements.Add(Der.ContextSpecific(718, Der.Integer(vendorPatchLevel)));
        }

        if (BootPatchLevel is long bootPatchLevel)
        {
            elements.Add(Der.ContextSpecific(719, Der.Integer(bootPatchLevel)));
        }

        return Der.Sequence(elements.ToArray());
    }
}

/// <summary>
/// Builds a KeyDescription extension payload, shaped after the structure measured on a real
/// device and corruptible one field at a time.
/// </summary>
/// <remarks>
/// The defaults are the structure of a genuine record, not the values of one. No value
/// measured from a device vector is written here: a package name, a digest or a challenge
/// copied out of a vector and into the repository would be the vector itself, arriving by a
/// slower route.
/// </remarks>
internal sealed class KeyDescriptionBuilder
{
    /// <summary>The attestation record format version.</summary>
    public long AttestationVersion { get; set; } = 300;

    /// <summary>The security level of the attestation record.</summary>
    public long AttestationSecurityLevel { get; set; } = 1;

    /// <summary>The keymaster or KeyMint version.</summary>
    public long KeymasterVersion { get; set; } = 300;

    /// <summary>The security level of the keymaster or KeyMint implementation.</summary>
    public long KeymasterSecurityLevel { get; set; } = 1;

    /// <summary>The challenge, 32 arbitrary bytes by default.</summary>
    public byte[] AttestationChallenge { get; set; } =
        Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();

    /// <summary>The unique identifier, empty by default, as measured on a real device.</summary>
    public byte[] UniqueId { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// The length to declare on the challenge OCTET STRING. Null declares the true length;
    /// a larger value produces a record that claims more bytes than it carries.
    /// </summary>
    public int? DeclaredChallengeLength { get; set; }

    /// <summary>The software-enforced list.</summary>
    public AuthorizationListBuilder SoftwareEnforced { get; } = new AuthorizationListBuilder();

    /// <summary>The hardware-enforced list.</summary>
    public AuthorizationListBuilder HardwareEnforced { get; } = new AuthorizationListBuilder();

    /// <summary>
    /// Builds a record with the field arrangement measured on a real device: the
    /// application identity in the software-enforced list, the origin and root of trust in
    /// the hardware-enforced one.
    /// </summary>
    public static KeyDescriptionBuilder RealisticLayout()
    {
        KeyDescriptionBuilder builder = new KeyDescriptionBuilder();

        builder.SoftwareEnforced.CreationDateTime = 1_700_000_000_000;
        builder.SoftwareEnforced.AttestationApplicationId = EncodeAttestationApplicationId(
            new[] { ("com.example.builder", 1L) },
            new[] { Enumerable.Range(0, 32).Select(i => (byte)(0x10 + i)).ToArray() });

        builder.HardwareEnforced.Purpose.Add(2);
        builder.HardwareEnforced.Algorithm = 3;
        builder.HardwareEnforced.KeySize = 256;
        builder.HardwareEnforced.Digest.Add(4);
        builder.HardwareEnforced.EcCurve = 1;
        builder.HardwareEnforced.NoAuthRequired = true;
        builder.HardwareEnforced.Origin = 0;
        builder.HardwareEnforced.RootOfTrust = new RootOfTrustBuilder();
        builder.HardwareEnforced.OsVersion = 160000;
        builder.HardwareEnforced.OsPatchLevel = 202607;
        builder.HardwareEnforced.VendorPatchLevel = 20260705;
        builder.HardwareEnforced.BootPatchLevel = 20260705;

        return builder;
    }

    /// <summary>Encodes the nested attestationApplicationId document.</summary>
    /// <param name="packages">The package names and version codes.</param>
    /// <param name="signatureDigests">The signing certificate digests.</param>
    public static byte[] EncodeAttestationApplicationId(
        IEnumerable<(string PackageName, long Version)> packages,
        IEnumerable<byte[]> signatureDigests)
    {
        byte[][] packageElements = packages
            .Select(p => Der.Sequence(
                Der.OctetString(System.Text.Encoding.UTF8.GetBytes(p.PackageName)),
                Der.Integer(p.Version)))
            .ToArray();

        byte[][] digestElements = signatureDigests
            .Select(d => Der.OctetString(d))
            .ToArray();

        return Der.Sequence(Der.Set(packageElements), Der.Set(digestElements));
    }

    /// <summary>Encodes the whole KeyDescription.</summary>
    public byte[] Build()
    {
        byte[] challenge = DeclaredChallengeLength is int declared
            ? Der.EncodeWithDeclaredLength(Der.OctetStringTag, declared, AttestationChallenge)
            : Der.OctetString(AttestationChallenge);

        return Der.Sequence(
            Der.Integer(AttestationVersion),
            Der.Enumerated(AttestationSecurityLevel),
            Der.Integer(KeymasterVersion),
            Der.Enumerated(KeymasterSecurityLevel),
            challenge,
            Der.OctetString(UniqueId),
            SoftwareEnforced.Build(),
            HardwareEnforced.Build());
    }
}
