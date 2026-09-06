using System.Buffers.Binary;
using MobileAttest.Apple;
using MobileAttest.Tests.TestSupport;

namespace MobileAttest.Tests.Apple;

/// <summary>
/// Boundary and shape tests for the only parser in the library that reads
/// attacker-controlled bytes.
/// </summary>
/// <remarks>
/// Most inputs here are built in the test, so they run without a device vector. The two
/// marked <see cref="FixtureFactAttribute"/> use the real capture, because the defect this
/// task fixes was found by running real bytes through the parser and would not have been
/// found by a synthetic input alone.
/// </remarks>
public class AuthenticatorDataTests
{
    private const byte AttestedCredentialDataFlag = 0x40;

    /// <summary>
    /// Builds authenticator data with attested credential data present.
    /// </summary>
    /// <param name="signCount">The counter to encode big endian.</param>
    /// <param name="credentialId">The credential identifier to embed.</param>
    /// <param name="credentialPublicKey">The trailing key bytes.</param>
    /// <param name="declaredCredentialIdLength">
    /// The length to write into the length field. Defaults to the real length; a test can
    /// pass a larger value to simulate a lying device.
    /// </param>
    private static byte[] BuildAuthenticatorData(
        uint signCount,
        byte[] credentialId,
        byte[] credentialPublicKey,
        int? declaredCredentialIdLength = null)
    {
        byte[] aaguid = System.Text.Encoding.ASCII.GetBytes("appattestdevelop");
        Assert.Equal(16, aaguid.Length);

        int declared = declaredCredentialIdLength ?? credentialId.Length;

        List<byte> buffer = new List<byte>(BuildPrefix(AttestedCredentialDataFlag, signCount));
        buffer.AddRange(aaguid);
        buffer.Add((byte)(declared >> 8));
        buffer.Add((byte)declared);
        buffer.AddRange(credentialId);
        buffer.AddRange(credentialPublicKey);
        return buffer.ToArray();
    }

    /// <summary>
    /// Builds the 37-byte prefix shared by both messages: hash, flags and counter.
    /// </summary>
    /// <param name="flags">The flags byte to write.</param>
    /// <param name="signCount">The counter to encode big endian.</param>
    private static byte[] BuildPrefix(byte flags, uint signCount)
    {
        byte[] prefix = new byte[AuthenticatorData.MinimumLength];
        for (int i = 0; i < AuthenticatorData.RpIdHashLength; i++)
        {
            prefix[i] = (byte)i;
        }

        prefix[AuthenticatorData.RpIdHashLength] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(prefix.AsSpan(AuthenticatorData.RpIdHashLength + 1), signCount);
        return prefix;
    }

    [Fact]
    public void AC8_AuthData_AttestationShape_ValidLayout_ParsesAllFields()
    {
        byte[] credentialId = Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + (i % 16))).ToArray();
        byte[] credentialPublicKey = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        byte[] raw = BuildAuthenticatorData(0, credentialId, credentialPublicKey);

        bool parsed = AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? authData);

        Assert.True(parsed);
        Assert.NotNull(authData);

        // Each assertion pins one offset. A single inserted or dropped byte anywhere in
        // the layout moves at least one of these.
        Assert.Equal(Enumerable.Range(0, 32).Select(i => (byte)i), authData!.RpIdHash.ToArray());
        Assert.Equal(AttestedCredentialDataFlag, authData.Flags);
        Assert.Equal(AuthenticatorDataShape.Attestation, authData.Shape);
        Assert.True(authData.HasAttestedCredentialData);
        Assert.Equal(0u, authData.SignCount);
        Assert.Equal("appattestdevelop", System.Text.Encoding.ASCII.GetString(authData.Aaguid.ToArray()));
        Assert.Equal(credentialId, authData.CredentialId.ToArray());
        Assert.Equal(credentialPublicKey, authData.CredentialPublicKey.ToArray());
    }

    [Fact]
    public void AC10_AuthData_BufferTooShort_IsRejected()
    {
        // One byte short of the minimum, and every shorter length down to empty.
        for (int length = 0; length < AuthenticatorData.MinimumLength; length++)
        {
            byte[] truncated = new byte[length];

            bool parsed = AuthenticatorData.TryParse(
                truncated,
                AuthenticatorDataShape.Attestation,
                out AuthenticatorData? authData);

            Assert.False(parsed);
            Assert.Null(authData);
        }

        // The flag promises attested credential data, but the buffer stops before the
        // length field. This must be rejected too, not read past the end.
        byte[] flagWithoutBody = new byte[AuthenticatorData.MinimumLength + 1];
        flagWithoutBody[32] = AttestedCredentialDataFlag;

        Assert.False(AuthenticatorData.TryParse(
            flagWithoutBody,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? incomplete));
        Assert.Null(incomplete);
    }

    [Fact]
    public void AC10_AuthData_CredentialIdLengthExceedsBuffer_IsRejected()
    {
        byte[] credentialId = new byte[8];
        byte[] raw = BuildAuthenticatorData(
            signCount: 0,
            credentialId: credentialId,
            credentialPublicKey: Array.Empty<byte>(),
            declaredCredentialIdLength: ushort.MaxValue);

        // The device claims 65535 bytes of credential id inside a buffer holding 8. A
        // parser that trusts the declared length either reads past the end or allocates
        // 64 KB per request.
        bool parsed = AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? authData);

        Assert.False(parsed);
        Assert.Null(authData);

        // Also reject a length that overshoots by exactly one byte.
        byte[] offByOne = BuildAuthenticatorData(
            signCount: 0,
            credentialId: credentialId,
            credentialPublicKey: Array.Empty<byte>(),
            declaredCredentialIdLength: credentialId.Length + 1);

        Assert.False(AuthenticatorData.TryParse(
            offByOne,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? overshoot));
        Assert.Null(overshoot);
    }

    [Fact]
    public void AC10_AuthData_SignCount_IsReadBigEndian()
    {
        byte[] raw = BuildAuthenticatorData(
            signCount: 0x01020304,
            credentialId: new byte[4],
            credentialPublicKey: Array.Empty<byte>());

        Assert.True(AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? authData));

        // Read little endian this would be 0x04030201. Clone detection compares counters,
        // so a byte-order mistake here makes a replayed counter look like a fresh one.
        Assert.Equal(0x01020304u, authData!.SignCount);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, raw.Skip(33).Take(4).ToArray());
    }

    [Fact]
    public void AC7_AuthData_AssertionShape_ThirtySevenBytesWithAtFlag_IsAccepted()
    {
        // The shape a device actually sends in an assertion: the attested-credential-data
        // bit is set, and no attested credential data follows it. Rejecting this rejects
        // real traffic, which is exactly what the previous signature did.
        byte[] raw = BuildPrefix(AttestedCredentialDataFlag, signCount: 7);

        bool parsed = AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Assertion,
            out AuthenticatorData? authData);

        Assert.True(parsed);
        Assert.NotNull(authData);
        Assert.Equal(AuthenticatorDataShape.Assertion, authData!.Shape);
        Assert.Equal(7u, authData.SignCount);

        // The raw bit is preserved, but it is not reported as a payload that is not there.
        Assert.Equal(AttestedCredentialDataFlag, authData.Flags & AttestedCredentialDataFlag);
        Assert.False(authData.HasAttestedCredentialData);
        Assert.True(authData.Aaguid.IsEmpty);
        Assert.True(authData.CredentialId.IsEmpty);
        Assert.True(authData.CredentialPublicKey.IsEmpty);
    }

    [Fact]
    public void AC8_AuthData_AttestationShape_ThirtySevenBytesWithAtFlag_IsRejected()
    {
        // Same 37 bytes, claimed to be an attestation. Accepting it would hand a verifier
        // an AuthenticatorData with an empty AAGUID and an empty credential id, so every
        // check made of those fields would compare against nothing and pass.
        byte[] raw = BuildPrefix(AttestedCredentialDataFlag, signCount: 7);

        Assert.False(AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? authData));
        Assert.Null(authData);

        // Neither does dropping the flag get an attestation through the same gap.
        byte[] withoutFlag = BuildPrefix(flags: 0x00, signCount: 7);

        Assert.False(AuthenticatorData.TryParse(
            withoutFlag,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? flagless));
        Assert.Null(flagless);
    }

    [Fact]
    public void AC7_AuthData_AssertionShape_ThirtyEightBytes_IsRejected()
    {
        // An assertion is exactly the prefix. A trailing byte is not ignored, because
        // whatever a verifier signs or logs afterwards would not cover it.
        byte[] tooLong = new byte[AuthenticatorData.MinimumLength + 1];
        BuildPrefix(AttestedCredentialDataFlag, signCount: 1).CopyTo(tooLong, 0);

        Assert.False(AuthenticatorData.TryParse(
            tooLong,
            AuthenticatorDataShape.Assertion,
            out AuthenticatorData? overlong));
        Assert.Null(overlong);

        // And one byte short is rejected on the other side of the same boundary.
        byte[] tooShort = BuildPrefix(AttestedCredentialDataFlag, signCount: 1)
            .Take(AuthenticatorData.MinimumLength - 1)
            .ToArray();

        Assert.False(AuthenticatorData.TryParse(
            tooShort,
            AuthenticatorDataShape.Assertion,
            out AuthenticatorData? truncated));
        Assert.Null(truncated);
    }

    [Fact]
    public void AC7_AuthData_AssertionShape_SignCount_IsReadBigEndian()
    {
        byte[] raw = BuildPrefix(AttestedCredentialDataFlag, signCount: 0x01020304);

        Assert.True(AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Assertion,
            out AuthenticatorData? authData));

        // The assertion counter is the one clone detection actually compares between
        // requests, so the endianness is pinned on this path too, not only the attestation.
        Assert.Equal(0x01020304u, authData!.SignCount);
        Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04 }, raw.Skip(33).Take(4).ToArray());
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public void AC7_RealAssertionAuthData_AssertionShape_IsAccepted()
    {
        // Measured 2026-09-05 against the T1 build: this exact input parsed as False. It
        // is the reason the shape parameter exists, so it is asserted on the real bytes
        // rather than on a reconstruction of them.
        byte[] raw = AppleVectorFile.Load().AssertionAuthenticatorData;

        Assert.Equal(AuthenticatorData.MinimumLength, raw.Length);
        Assert.Equal(
            AttestedCredentialDataFlag,
            raw[AuthenticatorData.RpIdHashLength] & AttestedCredentialDataFlag);

        bool parsed = AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Assertion,
            out AuthenticatorData? authData);

        Assert.True(parsed);
        Assert.NotNull(authData);
        Assert.False(authData!.HasAttestedCredentialData);
        Assert.True(authData.CredentialId.IsEmpty);

        // The counter is read from the vector rather than written into the test, so this
        // proves the field is decoded, not that someone copied the right number in.
        uint expected = BinaryPrimitives.ReadUInt32BigEndian(
            raw.AsSpan(AuthenticatorData.RpIdHashLength + 1, 4));
        Assert.Equal(expected, authData.SignCount);

        // The same bytes claimed as an attestation are still refused. Both halves of the
        // fix hold on real input, not only on the synthetic pair.
        Assert.False(AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? asAttestation));
        Assert.Null(asAttestation);
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public void AC8_RealAttestationAuthData_AttestationShape_ExposesAaguidAndCredentialId()
    {
        AppleVectorFile vector = AppleVectorFile.Load();
        byte[] raw = vector.AttestationAuthenticatorData;

        bool parsed = AuthenticatorData.TryParse(
            raw,
            AuthenticatorDataShape.Attestation,
            out AuthenticatorData? authData);

        Assert.True(parsed);
        Assert.NotNull(authData);
        Assert.True(authData!.HasAttestedCredentialData);
        Assert.Equal(AuthenticatorData.AaguidLength, authData.Aaguid.Length);
        Assert.False(authData.CredentialPublicKey.IsEmpty);

        // The credential identifier is the key identifier the device reported, and the
        // vector states that value itself. Comparing the parsed bytes against the vector's
        // own field keeps the real application identity out of this repository and still
        // pins the offset.
        Assert.Equal(vector.KeyIdBase64, Convert.ToBase64String(authData.CredentialId.ToArray()));
    }
}
