namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// Emits CBOR encodings byte by byte, including encodings a well-behaved writer would
/// never produce.
/// </summary>
/// <remarks>
/// <para>
/// The bytes are written here rather than produced by <c>CborWriter</c> on purpose. The
/// decoder under test is built on the same package that writer comes from, so building the
/// inputs with it would be asking the package whether it agrees with itself. Written out,
/// a test that passes says the decoder read a byte sequence, not that two halves of one
/// library round-tripped.
/// </para>
/// <para>
/// It is equally deliberate that this type can lie. A declared length that overruns its
/// payload, a map header promising members that are not there, a member holding the wrong
/// major type -- these are the inputs a device controls, so they have to be constructible.
/// Every method that can emit an inconsistent encoding says so on its parameters.
/// </para>
/// </remarks>
public static class CborBuilder
{
    private const int UnsignedIntegerMajorType = 0;
    private const int ByteStringMajorType = 2;
    private const int TextStringMajorType = 3;
    private const int ArrayMajorType = 4;
    private const int MapMajorType = 5;

    /// <summary>The format string a genuine Apple attestation statement carries.</summary>
    public const string AppleAttestationFormat = "apple-appattest";

    /// <summary>Joins encoded fragments into one encoding.</summary>
    /// <param name="parts">The fragments, in order.</param>
    public static byte[] Concat(params byte[][] parts)
    {
        int length = 0;

        foreach (byte[] part in parts)
        {
            length += part.Length;
        }

        byte[] joined = new byte[length];
        int offset = 0;

        foreach (byte[] part in parts)
        {
            part.CopyTo(joined, offset);
            offset += part.Length;
        }

        return joined;
    }

    /// <summary>
    /// Encodes an initial byte and its argument, in the shortest form that holds the value.
    /// </summary>
    /// <param name="majorType">The CBOR major type, 0 to 7.</param>
    /// <param name="argument">The argument the header declares.</param>
    /// <remarks>
    /// Shortest-form is what a genuine encoder emits, and strict conformance requires it of
    /// simple values. Using it everywhere keeps a test's failure attributable to the case it
    /// is testing rather than to an encoding the decoder rejected for an unrelated reason.
    /// </remarks>
    public static byte[] Header(int majorType, ulong argument)
    {
        byte prefix = (byte)(majorType << 5);

        if (argument < 24)
        {
            return new[] { (byte)(prefix | (byte)argument) };
        }

        if (argument <= byte.MaxValue)
        {
            return new[] { (byte)(prefix | 24), (byte)argument };
        }

        if (argument <= ushort.MaxValue)
        {
            return new[] { (byte)(prefix | 25), (byte)(argument >> 8), (byte)argument };
        }

        if (argument <= uint.MaxValue)
        {
            return new[]
            {
                (byte)(prefix | 26),
                (byte)(argument >> 24), (byte)(argument >> 16), (byte)(argument >> 8), (byte)argument,
            };
        }

        return new[]
        {
            (byte)(prefix | 27),
            (byte)(argument >> 56), (byte)(argument >> 48), (byte)(argument >> 40), (byte)(argument >> 32),
            (byte)(argument >> 24), (byte)(argument >> 16), (byte)(argument >> 8), (byte)argument,
        };
    }

    /// <summary>Encodes an unsigned integer.</summary>
    /// <param name="value">The value to encode.</param>
    public static byte[] UnsignedInteger(ulong value) => Header(UnsignedIntegerMajorType, value);

    /// <summary>Encodes a text string.</summary>
    /// <param name="value">The string to encode as UTF-8.</param>
    public static byte[] TextString(string value)
    {
        byte[] utf8 = System.Text.Encoding.UTF8.GetBytes(value);
        return Concat(Header(TextStringMajorType, (ulong)utf8.Length), utf8);
    }

    /// <summary>Encodes a byte string.</summary>
    /// <param name="value">The bytes to encode.</param>
    public static byte[] ByteString(byte[] value) =>
        Concat(Header(ByteStringMajorType, (ulong)value.Length), value);

    /// <summary>
    /// Encodes a byte string whose header declares a length the payload does not have.
    /// </summary>
    /// <param name="declaredLength">The length to write into the header.</param>
    /// <param name="payload">The bytes actually written after it.</param>
    /// <remarks>
    /// This is the overread case: a decoder that allocates or slices on the declared length
    /// before checking it against the buffer either reads past the end or spends the memory
    /// the sender asked for.
    /// </remarks>
    public static byte[] ByteStringWithDeclaredLength(ulong declaredLength, byte[] payload) =>
        Concat(Header(ByteStringMajorType, declaredLength), payload);

    /// <summary>Encodes a definite-length array header.</summary>
    /// <param name="declaredCount">The element count to write into the header.</param>
    public static byte[] ArrayHeader(ulong declaredCount) => Header(ArrayMajorType, declaredCount);

    /// <summary>Encodes a definite-length map header.</summary>
    /// <param name="declaredCount">The member count to write into the header.</param>
    /// <remarks>
    /// The count is passed rather than counted from the members, so a test can promise more
    /// members than it goes on to write.
    /// </remarks>
    public static byte[] MapHeader(ulong declaredCount) => Header(MapMajorType, declaredCount);

    /// <summary>Encodes an array of byte strings.</summary>
    /// <param name="elements">The elements, in order.</param>
    public static byte[] ByteStringArray(params byte[][] elements)
    {
        byte[][] parts = new byte[elements.Length + 1][];
        parts[0] = ArrayHeader((ulong)elements.Length);

        for (int i = 0; i < elements.Length; i++)
        {
            parts[i + 1] = ByteString(elements[i]);
        }

        return Concat(parts);
    }

    /// <summary>
    /// Encodes a chain of nested definite-length arrays around a single integer.
    /// </summary>
    /// <param name="depth">How many arrays to nest.</param>
    /// <remarks>
    /// The result is entirely well-formed, which is the point: a decoder must refuse it for
    /// its shape, at the outermost item, rather than descend it and run out of stack. An
    /// ill-formed input would be rejected for the wrong reason and would prove nothing.
    /// </remarks>
    public static byte[] NestedArrays(int depth)
    {
        byte[] encoded = new byte[depth + 1];

        for (int i = 0; i < depth; i++)
        {
            encoded[i] = (byte)((ArrayMajorType << 5) | 1);
        }

        encoded[depth] = 0x00;
        return encoded;
    }

    /// <summary>The certificates a well-formed synthetic attestation carries.</summary>
    /// <remarks>
    /// Byte patterns, not certificates. This decoder returns <c>x5c</c> elements as bytes
    /// and never parses them, so using real DER here would test nothing extra and would put
    /// certificate material into the repository.
    /// </remarks>
    public static IReadOnlyList<byte[]> SampleCertificateChain { get; } = new[]
    {
        new byte[] { 0x30, 0x82, 0x01, 0x01 },
        new byte[] { 0x30, 0x82, 0x02, 0x02, 0x02 },
    };

    /// <summary>The receipt a well-formed synthetic attestation carries.</summary>
    public static byte[] SampleReceipt { get; } = new byte[] { 0x52, 0x45, 0x43 };

    /// <summary>The authenticator data a well-formed synthetic attestation carries.</summary>
    public static byte[] SampleAuthenticatorData { get; } = new byte[] { 0xA0, 0xA1, 0xA2, 0xA3 };

    /// <summary>The signature a well-formed synthetic assertion carries.</summary>
    public static byte[] SampleSignature { get; } = new byte[] { 0x30, 0x44, 0x02, 0x20 };

    /// <summary>Builds an attestation object with every member present and consistent.</summary>
    public static byte[] WellFormedAttestationObject() => AttestationObject(
        AppleAttestationFormat,
        SampleCertificateChain,
        SampleReceipt,
        SampleAuthenticatorData);

    /// <summary>Builds an assertion object with both members present and consistent.</summary>
    public static byte[] WellFormedAssertionObject() => AssertionObject(
        SampleSignature,
        SampleAuthenticatorData);

    /// <summary>
    /// Builds an App Attest attestation object, omitting any member passed as null.
    /// </summary>
    /// <param name="format">The <c>fmt</c> value, or null to omit the member.</param>
    /// <param name="certificateChain">The <c>x5c</c> elements, or null to omit the member.</param>
    /// <param name="receipt">The <c>receipt</c> value, or null to omit the member.</param>
    /// <param name="authenticatorData">The <c>authData</c> value, or null to omit the member.</param>
    /// <remarks>
    /// The member counts in both map headers are derived from what is actually written, so
    /// an object built here is internally consistent. Producing an inconsistent one is done
    /// by composing the primitives above at the call site, where the inconsistency is
    /// visible in the test rather than hidden behind a flag.
    /// </remarks>
    public static byte[] AttestationObject(
        string? format,
        IReadOnlyList<byte[]>? certificateChain,
        byte[]? receipt,
        byte[]? authenticatorData)
    {
        List<byte[]> statement = new List<byte[]>();
        int statementMembers = 0;

        if (certificateChain is not null)
        {
            statement.Add(TextString("x5c"));
            statement.Add(ByteStringArray(certificateChain.ToArray()));
            statementMembers++;
        }

        if (receipt is not null)
        {
            statement.Add(TextString("receipt"));
            statement.Add(ByteString(receipt));
            statementMembers++;
        }

        statement.Insert(0, MapHeader((ulong)statementMembers));

        List<byte[]> outer = new List<byte[]>();
        int outerMembers = 0;

        if (format is not null)
        {
            outer.Add(TextString("fmt"));
            outer.Add(TextString(format));
            outerMembers++;
        }

        outer.Add(TextString("attStmt"));
        outer.Add(Concat(statement.ToArray()));
        outerMembers++;

        if (authenticatorData is not null)
        {
            outer.Add(TextString("authData"));
            outer.Add(ByteString(authenticatorData));
            outerMembers++;
        }

        outer.Insert(0, MapHeader((ulong)outerMembers));

        return Concat(outer.ToArray());
    }

    /// <summary>
    /// Builds an App Attest assertion object, omitting any member passed as null.
    /// </summary>
    /// <param name="signature">The <c>signature</c> value, or null to omit the member.</param>
    /// <param name="authenticatorData">
    /// The <c>authenticatorData</c> value, or null to omit the member.
    /// </param>
    public static byte[] AssertionObject(
        byte[]? signature,
        byte[]? authenticatorData)
    {
        List<byte[]> members = new List<byte[]>();
        int count = 0;

        if (signature is not null)
        {
            members.Add(TextString("signature"));
            members.Add(ByteString(signature));
            count++;
        }

        if (authenticatorData is not null)
        {
            members.Add(TextString("authenticatorData"));
            members.Add(ByteString(authenticatorData));
            count++;
        }

        members.Insert(0, MapHeader((ulong)count));

        return Concat(members.ToArray());
    }
}
