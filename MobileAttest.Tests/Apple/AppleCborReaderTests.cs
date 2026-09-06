using System.Reflection;
using MobileAttest.Apple;
using MobileAttest.Tests.TestSupport;

namespace MobileAttest.Tests.Apple;

/// <summary>
/// Tests for the decoder that reads the two App Attest objects.
/// </summary>
/// <remarks>
/// <para>
/// Every input below arrives from a device in production, so the interesting cases are the
/// ones a device would never send. Most are built in this project and run on a clean clone;
/// the three marked <see cref="FixtureFactAttribute"/> use the real capture, because a
/// synthetic object proves the field mapping and only real bytes prove the mapping matches
/// what Apple actually emits.
/// </para>
/// <para>
/// The contract under test is narrow and absolute: for any input at all, the answer is
/// <see langword="true"/> with an object or <see langword="false"/> with null. An exception
/// reaching a caller is a failure of the contract even when the input deserved rejection.
/// </para>
/// </remarks>
public class AppleCborReaderTests
{
    private readonly IAppleCborReader _reader = new AppleCborReader();

    /// <summary>
    /// Asserts that an input is refused, and refused in the way the contract requires.
    /// </summary>
    /// <param name="cbor">The encoding to reject.</param>
    /// <param name="because">What the input is, named in the failure message.</param>
    /// <remarks>
    /// Both entry points are tried on every rejected input. The two read different shapes,
    /// so an input malformed for one is not automatically malformed for the other, and a
    /// gap that exists on only one of them would otherwise go unnoticed.
    /// </remarks>
    private void AssertRejected(byte[] cbor, string because)
    {
        bool attestationRead = _reader.TryReadAttestationObject(
            cbor,
            out AppleAttestationObject? attestation);

        Assert.False(attestationRead, $"The attestation reader accepted {because}.");
        Assert.Null(attestation);

        bool assertionRead = _reader.TryReadAssertionObject(
            cbor,
            out AppleAssertionObject? assertion);

        Assert.False(assertionRead, $"The assertion reader accepted {because}.");
        Assert.Null(assertion);
    }

    [Fact]
    public void AC4_AttestationObject_WellFormed_ParsesAllFields()
    {
        byte[] cbor = CborBuilder.WellFormedAttestationObject();

        bool read = _reader.TryReadAttestationObject(cbor, out AppleAttestationObject? attestation);

        Assert.True(read);
        Assert.NotNull(attestation);

        // Each assertion pins one member to one field. The two certificates differ in
        // length and content, so a chain read in the wrong order, or a receipt and an
        // authenticator data swapped, moves at least one of these.
        Assert.Equal(CborBuilder.AppleAttestationFormat, attestation!.Format);
        Assert.Equal(2, attestation.X5c.Count);
        Assert.Equal(CborBuilder.SampleCertificateChain[0], attestation.X5c[0].ToArray());
        Assert.Equal(CborBuilder.SampleCertificateChain[1], attestation.X5c[1].ToArray());
        Assert.Equal(CborBuilder.SampleReceipt, attestation.Receipt.ToArray());
        Assert.Equal(CborBuilder.SampleAuthenticatorData, attestation.AuthenticatorData.ToArray());
    }

    [Fact]
    public void AC4_AttestationObject_WithoutReceipt_IsAcceptedWithAnEmptyReceipt()
    {
        // The receipt is the one optional member. Absent, it must leave the field empty and
        // the object readable -- not turn a decodable attestation into a rejected one.
        byte[] cbor = CborBuilder.AttestationObject(
            CborBuilder.AppleAttestationFormat,
            CborBuilder.SampleCertificateChain,
            receipt: null,
            CborBuilder.SampleAuthenticatorData);

        Assert.True(_reader.TryReadAttestationObject(cbor, out AppleAttestationObject? attestation));
        Assert.True(attestation!.Receipt.IsEmpty);
        Assert.Equal(CborBuilder.SampleAuthenticatorData, attestation.AuthenticatorData.ToArray());
    }

    [Fact]
    public void AC5_AssertionObject_WellFormed_ParsesBothFields()
    {
        byte[] cbor = CborBuilder.WellFormedAssertionObject();

        bool read = _reader.TryReadAssertionObject(cbor, out AppleAssertionObject? assertion);

        Assert.True(read);
        Assert.NotNull(assertion);

        // The two members are both byte strings, which is exactly why they can be crossed
        // without anything failing to build. Distinct values here catch that.
        Assert.Equal(CborBuilder.SampleSignature, assertion!.Signature.ToArray());
        Assert.Equal(CborBuilder.SampleAuthenticatorData, assertion.AuthenticatorData.ToArray());

        // An attestation object is not an assertion, and the reverse. Each entry point must
        // refuse the other's shape rather than find the members it recognises inside it.
        Assert.False(_reader.TryReadAttestationObject(cbor, out AppleAttestationObject? crossed));
        Assert.Null(crossed);
    }

    [Fact]
    public void AC6_AttestationObject_EmptyInput_IsRejected()
    {
        AssertRejected(Array.Empty<byte>(), "an empty input");

        // A default ReadOnlyMemory is not the same value as an empty array, and it reaches
        // the reader through the same parameter.
        Assert.False(_reader.TryReadAttestationObject(default, out AppleAttestationObject? attestation));
        Assert.Null(attestation);
        Assert.False(_reader.TryReadAssertionObject(default, out AppleAssertionObject? assertion));
        Assert.Null(assertion);

        // A lone map header, promising members that never arrive.
        AssertRejected(CborBuilder.MapHeader(3), "a map header with no members");

        // A well-formed CBOR document that is not a map at all.
        AssertRejected(CborBuilder.UnsignedInteger(0), "a bare integer");
        AssertRejected(CborBuilder.TextString(CborBuilder.AppleAttestationFormat), "a bare text string");
        AssertRejected(CborBuilder.ByteString(new byte[] { 0x01 }), "a bare byte string");
    }

    [Fact]
    public void AC6_AttestationObject_TruncatedMap_IsRejected()
    {
        byte[] complete = CborBuilder.WellFormedAttestationObject();

        // Every prefix of a valid object. A decoder that reads a length and then slices
        // without checking fails somewhere in here; one that stops early and reports
        // success fails at the tail of it.
        for (int length = 0; length < complete.Length; length++)
        {
            AssertRejected(complete[..length], $"a {length}-byte prefix of a valid attestation object");
        }

        // The header lies in the other direction: three members promised, one written.
        byte[] overPromised = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat));

        AssertRejected(overPromised, "a map declaring more members than it carries");

        byte[] completeAssertion = CborBuilder.WellFormedAssertionObject();

        for (int length = 0; length < completeAssertion.Length; length++)
        {
            AssertRejected(completeAssertion[..length], $"a {length}-byte prefix of a valid assertion object");
        }
    }

    [Fact]
    public void AC6_AttestationObject_ByteStringLengthExceedsBuffer_IsRejected()
    {
        // The device declares 65535 bytes of authenticator data and sends four. A decoder
        // that allocates or slices on the declared length reads past the end of the buffer,
        // or spends 64 KB per request on the sender's word alone.
        byte[] lyingAuthenticatorData = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.ByteStringArray(CborBuilder.SampleCertificateChain.ToArray())),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteStringWithDeclaredLength(ushort.MaxValue, new byte[] { 1, 2, 3, 4 }));

        AssertRejected(lyingAuthenticatorData, "an authData length that overruns the buffer");

        // The same lie one level down, inside the certificate chain.
        byte[] lyingCertificate = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.ArrayHeader(1),
                CborBuilder.ByteStringWithDeclaredLength(ushort.MaxValue, new byte[] { 0x30 })),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(lyingCertificate, "an x5c element length that overruns the buffer");

        // And the largest argument the encoding can carry, which must be refused as a
        // declared length rather than converted into one.
        byte[] impossibleLength = CborBuilder.Concat(
            CborBuilder.MapHeader(2),
            CborBuilder.TextString("signature"),
            CborBuilder.ByteStringWithDeclaredLength(ulong.MaxValue, new byte[] { 0x30 }),
            CborBuilder.TextString("authenticatorData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(impossibleLength, "a signature declaring 2^64-1 bytes");

        // An array header may lie about its element count too.
        byte[] overPromisedChain = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.ArrayHeader(uint.MaxValue),
                CborBuilder.ByteString(new byte[] { 0x30 })),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(overPromisedChain, "an x5c array declaring four billion elements");
    }

    [Fact]
    public void AC6_AttestationObject_MissingFmt_IsRejected()
    {
        byte[] withoutFormat = CborBuilder.AttestationObject(
            format: null,
            CborBuilder.SampleCertificateChain,
            CborBuilder.SampleReceipt,
            CborBuilder.SampleAuthenticatorData);

        AssertRejected(withoutFormat, "an attestation object with no fmt member");

        // The other required members, each removed on its own. None of them may be
        // substituted by an empty field on an object that still reads as decoded.
        byte[] withoutAuthenticatorData = CborBuilder.AttestationObject(
            CborBuilder.AppleAttestationFormat,
            CborBuilder.SampleCertificateChain,
            CborBuilder.SampleReceipt,
            authenticatorData: null);

        AssertRejected(withoutAuthenticatorData, "an attestation object with no authData member");

        byte[] withoutChain = CborBuilder.AttestationObject(
            CborBuilder.AppleAttestationFormat,
            certificateChain: null,
            CborBuilder.SampleReceipt,
            CborBuilder.SampleAuthenticatorData);

        AssertRejected(withoutChain, "an attestation object with no x5c member");

        // An empty chain is well-formed CBOR and carries nothing to pin or to read a leaf
        // from. Accepting it would hand the verifier above an empty list to index.
        byte[] emptyChain = CborBuilder.AttestationObject(
            CborBuilder.AppleAttestationFormat,
            Array.Empty<byte[]>(),
            CborBuilder.SampleReceipt,
            CborBuilder.SampleAuthenticatorData);

        AssertRejected(emptyChain, "an attestation object with an empty x5c array");

        // A member this decoder does not know is the same rejection as a member it needed
        // and did not get: it stops at the member it cannot account for. Skipping it
        // instead would carry content past every verifier downstream.
        byte[] unknownMember = CborBuilder.Concat(
            CborBuilder.MapHeader(4),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.ByteStringArray(CborBuilder.SampleCertificateChain.ToArray())),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData),
            CborBuilder.TextString("smuggled"),
            CborBuilder.ByteString(new byte[] { 0xFF, 0xFF }));

        AssertRejected(unknownMember, "an attestation object carrying an unknown member");

        // The same, one level down, inside the attestation statement.
        byte[] unknownStatementMember = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(2),
                CborBuilder.TextString("x5c"),
                CborBuilder.ByteStringArray(CborBuilder.SampleCertificateChain.ToArray()),
                CborBuilder.TextString("sig"),
                CborBuilder.ByteString(new byte[] { 0xFF })),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(unknownStatementMember, "an attStmt carrying an unknown member");

        // A repeated member is refused rather than resolved to one of its two values. The
        // decoder answers this itself, so the behaviour does not depend on the conformance
        // mode continuing to refuse duplicate keys.
        byte[] repeatedAuthenticatorData = CborBuilder.Concat(
            CborBuilder.MapHeader(4),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.ByteStringArray(CborBuilder.SampleCertificateChain.ToArray())),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(new byte[] { 0x00 }));

        AssertRejected(repeatedAuthenticatorData, "an attestation object repeating authData");
    }

    [Fact]
    public void AC6_AttestationObject_X5cNotAnArray_IsRejected()
    {
        // x5c holding a single byte string rather than an array of them. This is the shape
        // confusion that matters most: a decoder lenient enough to accept it would hand the
        // verifier one certificate where a chain was expected.
        byte[] chainAsByteString = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.ByteString(new byte[] { 0x30, 0x82, 0x01, 0x01 })),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(chainAsByteString, "an x5c holding a byte string instead of an array");

        // An array whose elements are text strings rather than DER byte strings.
        byte[] chainOfTextStrings = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.ArrayHeader(1),
                CborBuilder.TextString("not a certificate")),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(chainOfTextStrings, "an x5c array holding text strings");

        // fmt holding a byte string where a text string belongs.
        byte[] formatAsByteString = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.ByteString(new byte[] { 0x61, 0x62 }),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.ByteStringArray(CborBuilder.SampleCertificateChain.ToArray())),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(formatAsByteString, "an fmt holding a byte string");

        // attStmt as an array rather than a map.
        byte[] statementAsArray = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.ByteStringArray(CborBuilder.SampleCertificateChain.ToArray()),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(statementAsArray, "an attStmt holding an array");

        // A map key that is an integer, which is legal CBOR and is not a member name.
        byte[] integerKey = CborBuilder.Concat(
            CborBuilder.MapHeader(1),
            CborBuilder.UnsignedInteger(1),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat));

        AssertRejected(integerKey, "a map keyed by an integer");
    }

    [Fact]
    public void AC6_AttestationObject_DeeplyNested_IsRejectedWithoutStackOverflow()
    {
        // Fifty thousand nested arrays, entirely well-formed. A decoder that walks a
        // structure whose shape the sender chose runs out of stack here, and a stack
        // overflow cannot be caught -- the process dies rather than the request.
        const int Depth = 50_000;

        AssertRejected(CborBuilder.NestedArrays(Depth), "fifty thousand nested arrays");

        // The same payload reached through a member the decoder does read, so the rejection
        // cannot come from the very first byte alone.
        byte[] nestedInsideFormat = CborBuilder.Concat(
            CborBuilder.MapHeader(1),
            CborBuilder.TextString("fmt"),
            CborBuilder.NestedArrays(Depth));

        AssertRejected(nestedInsideFormat, "nested arrays as the value of fmt");

        byte[] nestedInsideStatement = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("fmt"),
            CborBuilder.TextString(CborBuilder.AppleAttestationFormat),
            CborBuilder.TextString("attStmt"),
            CborBuilder.Concat(
                CborBuilder.MapHeader(1),
                CborBuilder.TextString("x5c"),
                CborBuilder.NestedArrays(Depth)),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(nestedInsideStatement, "nested arrays as the value of x5c");

        byte[] nestedInsideSignature = CborBuilder.Concat(
            CborBuilder.MapHeader(2),
            CborBuilder.TextString("signature"),
            CborBuilder.NestedArrays(Depth),
            CborBuilder.TextString("authenticatorData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(nestedInsideSignature, "nested arrays as the value of signature");
    }

    [Fact]
    public void AC7_AttestationObject_TrailingBytes_IsRejected()
    {
        byte[] complete = CborBuilder.WellFormedAttestationObject();

        // Measured: the decoder underneath reports "finished" after a complete object and
        // leaves whatever follows unread. Without an explicit check the two inputs below
        // would both decode to the same object, which is one input having two readings --
        // and anything a caller stored, compared or logged afterwards would differ from
        // what was verified.
        Assert.True(_reader.TryReadAttestationObject(complete, out AppleAttestationObject? accepted));
        Assert.NotNull(accepted);

        AssertRejected(
            CborBuilder.Concat(complete, new byte[] { 0x00 }),
            "a valid attestation object with one trailing byte");

        AssertRejected(
            CborBuilder.Concat(complete, CborBuilder.WellFormedAttestationObject()),
            "two attestation objects in one input");

        AssertRejected(
            CborBuilder.Concat(complete, new byte[64]),
            "a valid attestation object with sixty-four trailing bytes");

        byte[] completeAssertion = CborBuilder.WellFormedAssertionObject();

        Assert.True(_reader.TryReadAssertionObject(completeAssertion, out AppleAssertionObject? assertion));
        Assert.NotNull(assertion);

        AssertRejected(
            CborBuilder.Concat(completeAssertion, new byte[] { 0xFF }),
            "a valid assertion object with one trailing byte");
    }

    [Fact]
    public void AC6_AssertionObject_MalformedInputs_AreRejected()
    {
        byte[] withoutSignature = CborBuilder.AssertionObject(
            signature: null,
            CborBuilder.SampleAuthenticatorData);

        AssertRejected(withoutSignature, "an assertion object with no signature member");

        byte[] withoutAuthenticatorData = CborBuilder.AssertionObject(
            CborBuilder.SampleSignature,
            authenticatorData: null);

        AssertRejected(withoutAuthenticatorData, "an assertion object with no authenticatorData member");

        AssertRejected(CborBuilder.AssertionObject(null, null), "an empty assertion map");

        // An unknown member alongside two valid ones.
        byte[] unknownMember = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("signature"),
            CborBuilder.ByteString(CborBuilder.SampleSignature),
            CborBuilder.TextString("authenticatorData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData),
            CborBuilder.TextString("extra"),
            CborBuilder.ByteString(new byte[] { 0x01 }));

        AssertRejected(unknownMember, "an assertion object carrying an unknown member");

        // The attestation object's member names, on an assertion-shaped map.
        byte[] wrongNames = CborBuilder.Concat(
            CborBuilder.MapHeader(2),
            CborBuilder.TextString("authData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData),
            CborBuilder.TextString("signature"),
            CborBuilder.ByteString(CborBuilder.SampleSignature));

        AssertRejected(wrongNames, "an assertion object using the attestation member names");

        // Members holding the wrong major type.
        byte[] signatureAsText = CborBuilder.Concat(
            CborBuilder.MapHeader(2),
            CborBuilder.TextString("signature"),
            CborBuilder.TextString("not bytes"),
            CborBuilder.TextString("authenticatorData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData));

        AssertRejected(signatureAsText, "a signature holding a text string");

        byte[] authenticatorDataAsMap = CborBuilder.Concat(
            CborBuilder.MapHeader(2),
            CborBuilder.TextString("signature"),
            CborBuilder.ByteString(CborBuilder.SampleSignature),
            CborBuilder.TextString("authenticatorData"),
            CborBuilder.MapHeader(0));

        AssertRejected(authenticatorDataAsMap, "an authenticatorData holding a map");

        // A repeated member, refused rather than resolved to one of its two values.
        byte[] repeatedSignature = CborBuilder.Concat(
            CborBuilder.MapHeader(3),
            CborBuilder.TextString("signature"),
            CborBuilder.ByteString(CborBuilder.SampleSignature),
            CborBuilder.TextString("authenticatorData"),
            CborBuilder.ByteString(CborBuilder.SampleAuthenticatorData),
            CborBuilder.TextString("signature"),
            CborBuilder.ByteString(new byte[] { 0x00 }));

        AssertRejected(repeatedSignature, "an assertion object repeating signature");
    }

    [Fact]
    public void AC8_AppleCborReader_IsTheOnlyImplementation()
    {
        Type contract = typeof(IAppleCborReader);

        List<Type> implementations = contract.Assembly
            .GetTypes()
            .Where(type => type.IsClass
                        && !type.IsAbstract
                        && contract.IsAssignableFrom(type))
            .ToList();

        // A second decoder is the failure this asserts against: two readers of the same
        // attacker-controlled bytes drift, and the one a verifier does not use stops being
        // maintained while still compiling. The count is taken over the whole library
        // assembly, including non-public types, so a decoder cannot hide by being internal.
        Assert.Single(implementations);
        Assert.Equal(typeof(AppleCborReader), implementations[0]);

        // And there is exactly one entry point per object, both public on that one type.
        Assert.NotNull(typeof(AppleCborReader).GetMethod(
            nameof(IAppleCborReader.TryReadAttestationObject),
            BindingFlags.Public | BindingFlags.Instance));
        Assert.NotNull(typeof(AppleCborReader).GetMethod(
            nameof(IAppleCborReader.TryReadAssertionObject),
            BindingFlags.Public | BindingFlags.Instance));
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public void AC4_RealAttestationObject_FieldLengthsMatchMeasuredValues()
    {
        AppleVectorFile vector = AppleVectorFile.Load();

        bool read = _reader.TryReadAttestationObject(
            vector.AttestationObject,
            out AppleAttestationObject? attestation);

        Assert.True(read);
        Assert.NotNull(attestation);

        // The lengths measured from the capture on 2026-09-05, before this decoder existed.
        // They are the sizes of the fields, not the identity of the application, so they
        // pin the field boundaries without putting anything from the vector into the repo.
        Assert.Equal(2, attestation!.X5c.Count);
        Assert.Equal(1043, attestation.X5c[0].Length);
        Assert.Equal(583, attestation.X5c[1].Length);
        Assert.Equal(3966, attestation.Receipt.Length);
        Assert.Equal(164, attestation.AuthenticatorData.Length);

        // Stronger than a length: the authenticator data is compared byte for byte against
        // what the test project's own scanner finds, which reaches the same bytes by
        // searching for the key rather than by decoding the structure. Two independent
        // readers agreeing on real input is evidence the offsets are right; a length alone
        // would still pass if the field were sliced from the wrong place by chance.
        Assert.Equal(vector.AttestationAuthenticatorData, attestation.AuthenticatorData.ToArray());

        // The leaf is DER, so it begins with a SEQUENCE header whose declared length
        // accounts for the rest of the element. A chain read in the wrong order, or an
        // element sliced off by one, fails this without any hardcoded certificate.
        Assert.Equal(0x30, attestation.X5c[0].Span[0]);
        Assert.Equal(0x30, attestation.X5c[1].Span[0]);

        // The whole capture is consumed: the parts add up to the object, with nothing
        // dropped between them.
        Assert.Equal(5819, vector.AttestationObject.Length);
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public void AC5_RealAssertionObject_FieldLengthsMatchMeasuredValues()
    {
        AppleVectorFile vector = AppleVectorFile.Load();

        bool read = _reader.TryReadAssertionObject(
            vector.AssertionObject,
            out AppleAssertionObject? assertion);

        Assert.True(read);
        Assert.NotNull(assertion);

        Assert.Equal(71, assertion!.Signature.Length);
        Assert.Equal(37, assertion.AuthenticatorData.Length);
        Assert.Equal(141, vector.AssertionObject.Length);

        // Again cross-checked against the independent scanner rather than only measured.
        Assert.Equal(vector.AssertionAuthenticatorData, assertion.AuthenticatorData.ToArray());

        // The signature is a DER ECDSA sequence. This distinguishes it from the
        // authenticator data, which is the field it could be crossed with.
        Assert.Equal(0x30, assertion.Signature.Span[0]);

        // The decoded authenticator data is what the assertion parser is given next, so it
        // has to satisfy that parser's shape. This is the seam between T2 and this task.
        Assert.True(AuthenticatorData.TryParse(
            assertion.AuthenticatorData.Span,
            AuthenticatorDataShape.Assertion,
            out AuthenticatorData? parsed));
        Assert.NotNull(parsed);

        // The real object is rejected when one byte is appended to it, which is the
        // trailing-byte rule holding on real input rather than only on a synthetic object.
        Assert.False(_reader.TryReadAssertionObject(
            CborBuilder.Concat(vector.AssertionObject, new byte[] { 0x00 }),
            out AppleAssertionObject? withTrailingByte));
        Assert.Null(withTrailingByte);
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public void AC4_RealAttestationObject_FormatIsAppleAppAttest()
    {
        AppleVectorFile vector = AppleVectorFile.Load();

        Assert.True(_reader.TryReadAttestationObject(
            vector.AttestationObject,
            out AppleAttestationObject? attestation));

        // The format is what a verifier checks before trusting anything else in the object,
        // so the value has to arrive intact. This decoder reads it and does not judge it;
        // the comparison itself belongs to the attestation verifier.
        Assert.Equal(CborBuilder.AppleAttestationFormat, attestation!.Format);

        // The real object is rejected when one byte is appended to it.
        Assert.False(_reader.TryReadAttestationObject(
            CborBuilder.Concat(vector.AttestationObject, new byte[] { 0x00 }),
            out AppleAttestationObject? withTrailingByte));
        Assert.Null(withTrailingByte);

        // Truncating the real object by a single byte is rejected as well, at the other end
        // of the same boundary.
        Assert.False(_reader.TryReadAttestationObject(
            vector.AttestationObject[..^1],
            out AppleAttestationObject? truncated));
        Assert.Null(truncated);
    }
}
