using System.Buffers.Binary;
using System.Text;
using MobileAttest.Abstractions;
using MobileAttest.Apple;
using MobileAttest.Tests.TestSupport;
using MobileAttest.Trust;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.Apple;

/// <summary>
/// Exercises the whole Apple path: the object, the chain, and the seven checks over what
/// the chain carries.
/// </summary>
/// <remarks>
/// <para>
/// The tests that need no vector build a synthetic attestation from a generated hierarchy:
/// a leaf carrying a nonce extension over authenticator data that names the leaf's own key.
/// Every value in it is invented here, so they run on a clean clone and put no device
/// material in the repository. What they prove is each check in isolation, including the
/// ones no vector we hold can reach -- a production AAGUID, a non-zero counter, an extension
/// with a second element hidden behind the one that parses.
/// </para>
/// <para>
/// The vector tests prove the same code on real device material, with every expected value
/// read out of the vector: the team identifier, the bundle identifier, the key identifier and
/// the challenge are never written here.
/// </para>
/// <para>
/// <b>Every test names the instant it evaluates at, and this is not optional.</b> The
/// vector's credential certificate was valid from 2026-09-03 07:35:43 to 2026-09-06 07:35:43
/// UTC -- three days, and they are past. A test left on the machine clock would fail from
/// 2026-09-06 onward and would read as a broken verifier rather than as an expired input.
/// The verifier takes the instant as an argument, so saying so costs a parameter rather than
/// a substitute clock.
/// </para>
/// <para>
/// <b>What these tests do prove about the trust root:</b> the vector's chain validates to
/// Apple's published App Attest root. The object carries its own intermediate in
/// <c>x5c</c>, so the root is the only anchor a caller supplies, and it is the anchor used
/// here.
/// </para>
/// </remarks>
public class AppleAppAttestVerifierTests
{
    /// <summary>An instant inside the window the vector's credential certificate is valid over.</summary>
    private static readonly DateTimeOffset InsideVectorWindow =
        new DateTimeOffset(2026, 9, 4, 12, 0, 0, TimeSpan.Zero);

    /// <summary>An instant after that certificate expired.</summary>
    private static readonly DateTimeOffset AfterVectorWindow =
        new DateTimeOffset(2026, 9, 7, 0, 0, 0, TimeSpan.Zero);

    /// <summary>An instant before it was issued.</summary>
    private static readonly DateTimeOffset BeforeVectorWindow =
        new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>An instant inside the window <see cref="TestChainBuilder"/> gives by default.</summary>
    private static readonly DateTimeOffset InsideSyntheticWindow =
        new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    // Invented identities. Nothing read from a device vector is written into this file.
    private const string SyntheticTeamId = "SYNTHTEAM1";
    private const string SyntheticBundleId = "com.example.synthetic";

    /// <summary>
    /// The two AAGUIDs App Attest defines, written out from their published form rather than
    /// read from the code under test, so these tests are an oracle and not a mirror.
    /// </summary>
    private static byte[] ProductionAaguid => Aaguid("appattest");

    private static byte[] DevelopmentAaguid => Aaguid("appattestdevelop");

    // ---------------------------------------------------------------- synthetic

    [Fact]
    public async Task AC12_Attestation_UnsupportedFormat_IsRejected()
    {
        // Everything else about this object is correct. Only the format string differs, so a
        // verifier that skipped the check would accept it.
        Synthetic synthetic = Synthetic.Create(DevelopmentAaguid, format: "packed");

        AttestationResult result = await synthetic.Verify(requireProduction: false);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.UnsupportedAttestationFormat, result.Reason);

        // And the same object with the format put back is accepted, which is what makes the
        // rejection attributable to the format and to nothing else.
        Synthetic accepted = Synthetic.Create(DevelopmentAaguid);
        Assert.True((await accepted.Verify(requireProduction: false)).IsValid);
    }

    [Fact]
    public async Task AC13_Attestation_NonZeroSignCount_IsRejected()
    {
        // A counter above zero says this key has signed before. A key being attested for the
        // first time cannot have done, so the claim and the counter contradict each other.
        Synthetic synthetic = Synthetic.Create(DevelopmentAaguid, signCount: 1);

        AttestationResult result = await synthetic.Verify(requireProduction: false);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.SignCountInvalid, result.Reason);

        // The counter is genuinely carried through on the accepting path rather than being
        // hardcoded to zero in the result.
        AttestationResult zero = await Synthetic.Create(DevelopmentAaguid).Verify(requireProduction: false);
        Assert.True(zero.IsValid);
        Assert.Equal(0u, zero.SignCount);
    }

    [Fact]
    public async Task AC14_Attestation_NonceExtensionMissing_IsRejected()
    {
        // A credential certificate with no nonce extension is not a smaller attestation. It
        // is an attestation with nothing binding it to the challenge that was issued, so the
        // step is refused rather than skipped.
        Synthetic synthetic = Synthetic.Create(DevelopmentAaguid, includeNonceExtension: false);

        AttestationResult result = await synthetic.Verify(requireProduction: false);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.MalformedAttestationExtension, result.Reason);
    }

    [Fact]
    public async Task AC14_Attestation_NonceExtensionMalformed_IsRejected()
    {
        // Each of these carries the correct nonce somewhere inside it. Only the structure is
        // wrong, so a reader that went looking for the bytes instead of parsing the shape
        // would accept every one of them.
        (string Description, Func<byte[], byte[]> Encode)[] cases =
        {
            ("the octet string with no tagged wrapper", nonce => Der.Sequence(Der.OctetString(nonce))),
            ("a bare octet string with no sequence", nonce => Der.OctetString(nonce)),
            (
                "a second element inside the sequence",
                nonce => Der.Sequence(
                    Der.ContextSpecific(1, Der.OctetString(nonce)),
                    Der.Integer(1))
            ),
            (
                "an integer where the nonce belongs",
                nonce => Der.Sequence(Der.ContextSpecific(1, Der.Integer(1)))
            ),
            (
                "the nonce under the wrong context tag",
                nonce => Der.Sequence(Der.ContextSpecific(2, Der.OctetString(nonce)))
            ),
        };

        foreach ((string description, Func<byte[], byte[]> encode) in cases)
        {
            Synthetic synthetic = Synthetic.Create(DevelopmentAaguid, encodeNonceExtension: encode);

            AttestationResult result = await synthetic.Verify(requireProduction: false);

            Assert.False(result.IsValid, $"an extension holding {description} was accepted");
            Assert.Equal(AttestationFailureReason.MalformedAttestationExtension, result.Reason);
        }
    }

    [Fact]
    public async Task AC14_NonceExtension_TrailingDataIgnoredByFallback_HasNoFallback()
    {
        // The shortcut this guards against: "take the last 32 bytes of the extension". Here
        // the structure parses and carries a decoy, and the real nonce is a second element
        // after it. A tail-reading implementation reads the last 32 bytes and accepts; this
        // one must refuse, because an extension with something extra in it has two readings
        // and no verifier may pick one.
        byte[] decoy = Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + i)).ToArray();

        Synthetic smuggled = Synthetic.Create(
            DevelopmentAaguid,
            encodeNonceExtension: nonce => Der.Sequence(
                Der.ContextSpecific(1, Der.OctetString(decoy)),
                Der.OctetString(nonce)));

        AttestationResult smuggledResult = await smuggled.Verify(requireProduction: false);

        Assert.False(smuggledResult.IsValid);
        Assert.Equal(AttestationFailureReason.MalformedAttestationExtension, smuggledResult.Reason);

        // The mirror case: the structure carries the right nonce and something follows it.
        // Rejected too, so the rule is "nothing may follow", not "the tail must be wrong".
        Synthetic appended = Synthetic.Create(
            DevelopmentAaguid,
            encodeNonceExtension: nonce => Der.Sequence(
                Der.ContextSpecific(1, Der.OctetString(nonce)),
                Der.Integer(1)));

        AttestationResult appendedResult = await appended.Verify(requireProduction: false);

        Assert.False(appendedResult.IsValid);
        Assert.Equal(AttestationFailureReason.MalformedAttestationExtension, appendedResult.Reason);

        // And the parser directly, with the shapes an X.509 encoder will not carry verbatim.
        // Those are exactly the ones a tail-reading implementation accepts, so they are
        // asserted where the guarantee is made rather than skipped for want of a carrier.
        byte[] wellFormed = Der.Sequence(Der.ContextSpecific(1, Der.OctetString(decoy)));

        Assert.True(AppleNonceExtension.TryParse(wellFormed, out byte[]? parsed));
        Assert.Equal(decoy, parsed);

        (string Description, byte[] Octets)[] directCases =
        {
            ("bytes appended after the whole structure", Der.Concat(wellFormed, decoy)),
            ("a single trailing byte", Der.Concat(wellFormed, new byte[] { 0x00 })),
            (
                "a second element inside the tagged wrapper",
                Der.Sequence(Der.ContextSpecific(1, Der.Concat(Der.OctetString(decoy), Der.Integer(1))))
            ),
            ("the nonce as a raw 32-byte value", decoy),
            ("not DER at all", Encoding.ASCII.GetBytes("this is not an extension")),
            ("nothing at all", Array.Empty<byte>()),
            (
                "a length that overstates the payload",
                Der.Sequence(
                    Der.ContextSpecific(
                        1,
                        Der.EncodeWithDeclaredLength(Der.OctetStringTag, decoy.Length + 16, decoy)))
            ),
        };

        foreach ((string description, byte[] octets) in directCases)
        {
            Assert.False(
                AppleNonceExtension.TryParse(octets, out byte[]? none),
                $"an extension holding {description} was read");
            Assert.Null(none);
        }
    }

    [Fact]
    public async Task AC15_Attestation_MalformedInputs_ReturnResultNotException()
    {
        Synthetic synthetic = Synthetic.Create(DevelopmentAaguid);
        AppleAppAttestVerifier verifier =
            new AppleAppAttestVerifier(synthetic.Options(requireProduction: false));

        // A null request is the one exception the contract declares, and it stays an
        // exception: it is a mistake in the calling code, not something a device can send.
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => verifier.VerifyAsync(null!, InsideSyntheticWindow));

        byte[] authenticatorData = synthetic.AuthenticatorData;

        (string Description, AttestationRequest Request)[] cases =
        {
            (
                "a request from another platform",
                new AndroidAttestationRequest(
                    new ReadOnlyMemory<byte>[] { synthetic.Chain.Leaf.GetEncoded() },
                    synthetic.Challenge)
            ),
            ("an empty attestation object", synthetic.RequestWith(Array.Empty<byte>())),
            ("text instead of CBOR", synthetic.RequestWith(Encoding.ASCII.GetBytes("not CBOR"))),
            (
                "an object truncated halfway",
                synthetic.RequestWith(synthetic.AttestationObject.AsSpan(0, 40).ToArray())
            ),
            (
                "a trailing byte after a complete object",
                synthetic.RequestWith(CborBuilder.Concat(synthetic.AttestationObject, new byte[] { 0x00 }))
            ),
            (
                "an empty certificate chain",
                synthetic.RequestWith(CborBuilder.AttestationObject(
                    AppleAppAttestVerifier.AttestationFormat,
                    Array.Empty<byte[]>(),
                    CborBuilder.SampleReceipt,
                    authenticatorData))
            ),
            (
                "a chain element that is not a certificate",
                synthetic.RequestWith(CborBuilder.AttestationObject(
                    AppleAppAttestVerifier.AttestationFormat,
                    new[] { Encoding.ASCII.GetBytes("not a certificate at all") },
                    CborBuilder.SampleReceipt,
                    authenticatorData))
            ),
            (
                "a chain element declaring a length far past the input",
                synthetic.RequestWith(CborBuilder.AttestationObject(
                    AppleAppAttestVerifier.AttestationFormat,
                    new[] { new byte[] { 0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF } },
                    CborBuilder.SampleReceipt,
                    authenticatorData))
            ),
            (
                "no authenticator data at all",
                synthetic.RequestWith(CborBuilder.AttestationObject(
                    AppleAppAttestVerifier.AttestationFormat,
                    synthetic.Chain.Der,
                    CborBuilder.SampleReceipt,
                    authenticatorData: null))
            ),
            (
                "authenticator data cut short",
                synthetic.RequestWith(synthetic.ObjectWithAuthenticatorData(
                    authenticatorData.AsSpan(0, 20).ToArray()))
            ),
            (
                "authenticator data that stops before its credential identifier",
                synthetic.RequestWith(synthetic.ObjectWithAuthenticatorData(
                    authenticatorData.AsSpan(0, 54).ToArray()))
            ),
            (
                "a credential identifier length past the end of the buffer",
                synthetic.RequestWith(synthetic.ObjectWithAuthenticatorData(
                    WithCredentialIdLength(authenticatorData, ushort.MaxValue)))
            ),
            (
                "an empty challenge",
                synthetic.RequestWith(synthetic.AttestationObject, challenge: Array.Empty<byte>())
            ),
            (
                "an empty key identifier",
                synthetic.RequestWith(synthetic.AttestationObject, keyId: Array.Empty<byte>())
            ),
        };

        foreach ((string description, AttestationRequest request) in cases)
        {
            AttestationResult? result = null;
            Exception? thrown = await Record.ExceptionAsync(async () =>
                result = await verifier.VerifyAsync(request, InsideSyntheticWindow));

            Assert.True(
                thrown is null,
                $"verifying {description} threw {thrown?.GetType().Name}: {thrown?.Message}");

            Assert.NotNull(result);
            Assert.False(result!.IsValid, $"verifying {description} was accepted");

            // A rejection with no reason reads as a success in every log and comparison
            // downstream, so the reason being present is part of the contract.
            Assert.NotEqual(AttestationFailureReason.None, result.Reason);
            Assert.Equal(Platform.Apple, result.Platform);

            // A failed result carries no attested material, whatever went wrong.
            Assert.Null(result.AppId);
            Assert.True(result.KeyId.IsEmpty);
            Assert.True(result.PublicKeyDer.IsEmpty);
            Assert.True(result.Receipt.IsEmpty);
            Assert.Equal(AttestationEnvironment.Unknown, result.Environment);
        }
    }

    [Fact]
    public async Task AC8_Attestation_ProductionAaguid_IsAcceptedWhenProductionRequired()
    {
        // The default policy, unmodified: RequireProduction is left where the options put it.
        Synthetic synthetic = Synthetic.Create(ProductionAaguid);

        AppleAttestOptions options = new AppleAttestOptions
        {
            TeamId = SyntheticTeamId,
            BundleIdAllowlist = new[] { SyntheticBundleId },
            PinnedRootCertificates = synthetic.Chain.PinnedRoots,
        };

        Assert.True(options.RequireProduction, "the default policy is expected to require production");

        AttestationResult result = await new AppleAppAttestVerifier(options)
            .VerifyAsync(synthetic.Request(), InsideSyntheticWindow);

        Assert.True(result.IsValid, $"a production key was refused with {result.Reason}");
        Assert.Equal(AttestationEnvironment.Production, result.Environment);
        Assert.Equal($"{SyntheticTeamId}.{SyntheticBundleId}", result.AppId);

        // An AAGUID that is neither of the two Apple defines cannot travel on a successful
        // result as Unknown, whatever the policy says, because a caller reading Unknown could
        // not tell "we could not tell" from "this platform has no such notion".
        Synthetic unknown = Synthetic.Create(Aaguid("appattestmystery"));

        foreach (bool requireProduction in new[] { true, false })
        {
            AttestationResult unknownResult = await unknown.Verify(requireProduction);

            Assert.False(unknownResult.IsValid);
            Assert.Equal(AttestationFailureReason.MalformedAuthenticatorData, unknownResult.Reason);
        }
    }

    [Fact]
    public async Task AC5_Attestation_NonceComparison_UsesFixedTime()
    {
        // Timing itself is not asserted, because a unit test cannot measure it reliably. What
        // is asserted is that the comparison answers correctly wherever the difference sits:
        // a comparison that returned early on the first byte would still have to be wrong to
        // fail this, and one that was right only near the front would pass a weaker test.
        Synthetic synthetic = Synthetic.Create(DevelopmentAaguid);

        byte[] firstByteFlipped = (byte[])synthetic.Challenge.Clone();
        firstByteFlipped[0] ^= 0xFF;

        byte[] lastByteFlipped = (byte[])synthetic.Challenge.Clone();
        lastByteFlipped[lastByteFlipped.Length - 1] ^= 0xFF;

        byte[][] mutations =
        {
            firstByteFlipped,
            lastByteFlipped,
            Array.Empty<byte>(),
            synthetic.Challenge.Concat(new byte[] { 0x00 }).ToArray(),
        };

        foreach (byte[] challenge in mutations)
        {
            AttestationResult result = await synthetic.Verify(requireProduction: false, challenge: challenge);

            Assert.False(result.IsValid);
            Assert.Equal(AttestationFailureReason.NonceMismatch, result.Reason);
        }

        // The unmutated challenge still passes, so the rejections above are attributable to
        // the mutation rather than to a nonce step that refuses everything.
        Assert.True((await synthetic.Verify(requireProduction: false)).IsValid);
    }

    [Fact]
    public async Task AC11_Attestation_NoPinnedRoots_ReturnsRootNotPinned()
    {
        Synthetic synthetic = Synthetic.Create(DevelopmentAaguid);

        // No anchor at all. The verifier has no default Apple root to fall back to, because
        // no such default exists anywhere in this library.
        AppleAttestOptions unconfigured = new AppleAttestOptions
        {
            TeamId = SyntheticTeamId,
            BundleIdAllowlist = new[] { SyntheticBundleId },
            RequireProduction = false,
            PinnedRootCertificates = Array.Empty<X509Certificate>(),
        };

        AttestationResult unconfiguredResult = await new AppleAppAttestVerifier(unconfigured)
            .VerifyAsync(synthetic.Request(), InsideSyntheticWindow);

        Assert.False(unconfiguredResult.IsValid);
        Assert.Equal(AttestationFailureReason.RootNotPinned, unconfiguredResult.Reason);

        // An anchor that is real but is not this chain's is refused the same way.
        AppleAttestOptions stranger = new AppleAttestOptions
        {
            TeamId = SyntheticTeamId,
            BundleIdAllowlist = new[] { SyntheticBundleId },
            RequireProduction = false,
            PinnedRootCertificates = TestChainBuilder.Create("Unrelated Authority").PinnedRoots,
        };

        AttestationResult strangerResult = await new AppleAppAttestVerifier(stranger)
            .VerifyAsync(synthetic.Request(), InsideSyntheticWindow);

        Assert.False(strangerResult.IsValid);
        Assert.Equal(AttestationFailureReason.RootNotPinned, strangerResult.Reason);
    }

    // ------------------------------------------------------------ device vector

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task AC4_RealAttestation_WithDerivedOptions_IsValid()
    {
        VectorInputs vector = VectorInputs.Load();

        AttestationResult result = await vector.Verify();

        Assert.True(result.IsValid, $"the vector was refused with {result.Reason}");
        Assert.Equal(AttestationFailureReason.None, result.Reason);
        Assert.Equal(Platform.Apple, result.Platform);

        // Development, decided from the AAGUID alone. The vector's metadata says the same
        // thing, and the verifier never reads it.
        Assert.Equal(AttestationEnvironment.Development, result.Environment);

        // The identifier the verifier recomputed from Apple's certificate is the one the
        // device reported. This is the assertion the whole EC derivation exists for, and the
        // expected value comes from a real device rather than from anything in this repo.
        Assert.Equal(vector.KeyId, result.KeyId.ToArray());

        Assert.Equal($"{vector.Vector.TeamId}.{vector.Vector.BundleId}", result.AppId);
        Assert.Equal(0u, result.SignCount);
        Assert.Equal(3966, result.Receipt.Length);

        // The attested key is returned as the certificate carries it, so a caller storing it
        // and a caller reading the same certificate arrive at the same bytes.
        Assert.Equal(
            vector.CredentialCertificate.SubjectPublicKeyInfo.GetDerEncoded(),
            result.PublicKeyDer.ToArray());

        // The anchor is Apple's own published root, not an intermediate the device sent. The
        // intermediate travels inside the object, so this is a chain validated end to end.
        Assert.Equal(
            "CN=Apple App Attestation Root CA,O=Apple Inc.,ST=California",
            vector.AppleRoot.SubjectDN.ToString());
        Assert.True(
            vector.AppleRoot.SubjectDN.Equivalent(vector.AppleRoot.IssuerDN, true),
            "the anchor is expected to be self-signed");
    }

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task AC5_RealAttestation_MutatedChallenge_ReturnsNonceMismatch()
    {
        VectorInputs vector = VectorInputs.Load();

        // The accepting case takes its challenge from the vector, so on its own it does not
        // show that the comparison bites. One byte is flipped here, and nothing else changes.
        byte[] mutated = (byte[])vector.Challenge.Clone();
        mutated[7] ^= 0xFF;

        AttestationResult result = await vector.Verify(challenge: mutated);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.NonceMismatch, result.Reason);
    }

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task AC6_RealAttestation_WrongTeamId_ReturnsRpIdHashMismatch()
    {
        VectorInputs vector = VectorInputs.Load();

        AttestationResult result = await vector.Verify(teamId: "WRONGTEAM1");

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.RpIdHashMismatch, result.Reason);
    }

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task AC7_RealAttestation_BundleIdNotInAllowlist_IsRejected()
    {
        VectorInputs vector = VectorInputs.Load();

        // The team identifier is the vector's own; only the allowlist is wrong.
        //
        // The reason is RpIdHashMismatch and not BundleIdNotAllowed, deliberately. The hash
        // covers the team identifier and the bundle identifier together and gives back one
        // bit, so "the team is right and the bundle is wrong" is not something this or any
        // other verifier can establish. Reporting BundleIdNotAllowed here would be claiming
        // to know which bundle identifier the device attested, and nothing measured it.
        AttestationResult result = await vector.Verify(
            bundleIds: new[] { "com.example.not-this-one" });

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.RpIdHashMismatch, result.Reason);

        // BundleIdNotAllowed is the answer to the one question the verifier can answer: an
        // allowlist with nothing in it allows nothing, and there is no identity to offer the
        // hash at all.
        AttestationResult empty = await vector.Verify(bundleIds: Array.Empty<string>());

        Assert.False(empty.IsValid);
        Assert.Equal(AttestationFailureReason.BundleIdNotAllowed, empty.Reason);

        // The vector's own bundle identifier still passes, so both rejections are
        // attributable to the allowlist rather than to a step that refuses everything. An
        // allowlist holding several entries, one of which is the vector's, passes too -- the
        // match is a search, not a comparison against a single configured value.
        Assert.True((await vector.Verify()).IsValid);
        Assert.True((await vector.Verify(
            bundleIds: new[] { "com.example.first", vector.Vector.BundleId, "com.example.last" })).IsValid);
    }

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task AC8_RealAttestation_RequireProductionDefault_ReturnsDevelopmentKeyInProduction()
    {
        VectorInputs vector = VectorInputs.Load();

        // RequireProduction is not set anywhere below. The point of the test is the default:
        // a development key must be refused by a caller who configured nothing about it.
        AppleAttestOptions options = new AppleAttestOptions
        {
            TeamId = vector.Vector.TeamId,
            BundleIdAllowlist = new[] { vector.Vector.BundleId },
            PinnedRootCertificates = new[] { vector.AppleRoot },
        };

        Assert.True(options.RequireProduction, "the default policy is expected to require production");

        AttestationResult result = await new AppleAppAttestVerifier(options)
            .VerifyAsync(vector.Request(), InsideVectorWindow);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.DevelopmentKeyInProduction, result.Reason);
    }

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task AC9_RealAttestation_MutatedKeyId_ReturnsKeyIdMismatch()
    {
        VectorInputs vector = VectorInputs.Load();

        // The identifier the device sends alongside the object is a claim, not evidence. It
        // is compared against one recomputed from Apple's certificate, so a device that names
        // a different key than the one it attested is refused.
        byte[] mutated = (byte[])vector.KeyId.Clone();
        mutated[0] ^= 0xFF;

        AttestationResult result = await vector.Verify(keyId: mutated);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.KeyIdMismatch, result.Reason);

        // A truncated identifier is a mismatch too, not a shorter comparison that happens to
        // agree on the bytes it covers.
        AttestationResult truncated = await vector.Verify(keyId: vector.KeyId.AsSpan(0, 16).ToArray());

        Assert.False(truncated.IsValid);
        Assert.Equal(AttestationFailureReason.KeyIdMismatch, truncated.Reason);
    }

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task AC10_RealAttestation_ClockAfterCredCertExpiry_ReturnsCertificateExpired()
    {
        VectorInputs vector = VectorInputs.Load();

        // The trap this test exists to make visible. The vector's credential certificate was
        // valid from 2026-09-03 07:35:43 to 2026-09-06 07:35:43 UTC -- App Attest issues
        // three-day certificates, and this one lapsed hours after the vector was captured.
        //
        // Because the instant is an argument, one verifier answers both questions and the
        // expiry is asked for on purpose rather than discovered later as a regression.
        AttestationResult afterExpiry = await vector.Verify(evaluationTime: AfterVectorWindow);

        Assert.False(afterExpiry.IsValid);
        Assert.Equal(AttestationFailureReason.CertificateExpired, afterExpiry.Reason);

        // The other edge, so the window is closed at both ends rather than only at the top.
        AttestationResult beforeIssue = await vector.Verify(evaluationTime: BeforeVectorWindow);

        Assert.False(beforeIssue.IsValid);
        Assert.Equal(AttestationFailureReason.CertificateExpired, beforeIssue.Reason);

        // And inside the window it passes, which is what makes the two rejections above
        // statements about the instant rather than about the chain. All three answers come
        // from the same verifier instance: the instant belongs to the call, not to the object.
        AppleAppAttestVerifier verifier = new AppleAppAttestVerifier(vector.Options());

        Assert.True((await verifier.VerifyAsync(vector.Request(), InsideVectorWindow)).IsValid);
        Assert.False((await verifier.VerifyAsync(vector.Request(), AfterVectorWindow)).IsValid);
        Assert.True((await verifier.VerifyAsync(vector.Request(), InsideVectorWindow)).IsValid);

        // The overload without an instant still works and reads the constructor's clock, so
        // the contract method is not a path that quietly stopped being exercised.
        AttestationResult viaDefaultClock = await new AppleAppAttestVerifier(
                vector.Options(),
                new FixedTimeProvider(InsideVectorWindow))
            .VerifyAsync(vector.Request());

        Assert.True(viaDefaultClock.IsValid, $"the default-clock path refused with {viaDefaultClock.Reason}");
    }

    [FixtureFact(TestVectors.AppleVectorPath, TestVectors.AppleRootPath)]
    public async Task AC11_RealAttestation_ForeignAnchor_ReturnsRootNotPinned()
    {
        VectorInputs vector = VectorInputs.Load();

        AttestationResult foreign = await vector.Verify(
            roots: TestChainBuilder.Create("Unrelated Authority").PinnedRoots);

        Assert.False(foreign.IsValid);
        Assert.Equal(AttestationFailureReason.RootNotPinned, foreign.Reason);

        AttestationResult none = await vector.Verify(roots: Array.Empty<X509Certificate>());

        Assert.False(none.IsValid);
        Assert.Equal(AttestationFailureReason.RootNotPinned, none.Reason);
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>Builds a 16-byte AAGUID from its ASCII label, zero padded.</summary>
    private static byte[] Aaguid(string label)
    {
        byte[] value = new byte[16];
        Encoding.ASCII.GetBytes(label).CopyTo(value, 0);
        return value;
    }

    /// <summary>Rewrites the credential identifier length an authenticator data declares.</summary>
    private static byte[] WithCredentialIdLength(byte[] authenticatorData, ushort declaredLength)
    {
        byte[] copy = (byte[])authenticatorData.Clone();
        BinaryPrimitives.WriteUInt16BigEndian(copy.AsSpan(53, 2), declaredLength);
        return copy;
    }

    private static byte[] Sha256(params byte[][] parts)
    {
        Sha256Digest digest = new Sha256Digest();

        foreach (byte[] part in parts)
        {
            digest.BlockUpdate(part, 0, part.Length);
        }

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }

    /// <summary>
    /// One synthetic attestation: a generated hierarchy whose leaf carries a nonce extension
    /// over authenticator data that names the leaf's own key.
    /// </summary>
    /// <remarks>
    /// The three are circular in the real object, which is why they are built together here.
    /// The credential identifier is a digest of the leaf's key, the authenticator data
    /// carries the identifier, and the nonce is a digest over the authenticator data -- so
    /// the extension can only be written while the key is being generated.
    /// </remarks>
    private sealed class Synthetic
    {
        private Synthetic(
            TestChain chain,
            byte[] authenticatorData,
            byte[] attestationObject,
            byte[] challenge,
            byte[] keyId)
        {
            Chain = chain;
            AuthenticatorData = authenticatorData;
            AttestationObject = attestationObject;
            Challenge = challenge;
            KeyId = keyId;
        }

        public TestChain Chain { get; }

        public byte[] AuthenticatorData { get; }

        public byte[] AttestationObject { get; }

        public byte[] Challenge { get; }

        public byte[] KeyId { get; }

        public static Synthetic Create(
            byte[] aaguid,
            uint signCount = 0,
            string format = AppleAppAttestVerifier.AttestationFormat,
            bool includeNonceExtension = true,
            Func<byte[], byte[]>? encodeNonceExtension = null,
            string name = "Apple Synthetic")
        {
            byte[] challenge = Enumerable.Range(0, 32).Select(i => (byte)(i * 5)).ToArray();
            byte[] rpIdHash = Sha256(Encoding.UTF8.GetBytes($"{SyntheticTeamId}.{SyntheticBundleId}"));

            byte[]? authenticatorData = null;
            byte[]? keyId = null;

            TestChain chain = TestChainBuilder.Create(
                name,
                leafAppleNonceExtension: includeNonceExtension
                    ? publicKey =>
                    {
                        keyId = KeyIdOf(publicKey);
                        authenticatorData = BuildAuthenticatorData(rpIdHash, signCount, aaguid, keyId);

                        byte[] nonce = Sha256(authenticatorData, Sha256(challenge));

                        return encodeNonceExtension is null
                            ? Der.Sequence(Der.ContextSpecific(1, Der.OctetString(nonce)))
                            : encodeNonceExtension(nonce);
                    }
                    : null);

            if (authenticatorData is null)
            {
                // The extension was omitted, so nothing built the authenticator data during
                // issuance. The leaf's key is the same key either way.
                keyId = KeyIdOf(chain.Leaf);
                authenticatorData = BuildAuthenticatorData(rpIdHash, signCount, aaguid, keyId);
            }

            byte[] attestationObject = CborBuilder.AttestationObject(
                format,
                chain.Der,
                CborBuilder.SampleReceipt,
                authenticatorData);

            return new Synthetic(chain, authenticatorData, attestationObject, challenge, keyId!);
        }

        public AppleAttestOptions Options(bool requireProduction) =>
            new AppleAttestOptions
            {
                TeamId = SyntheticTeamId,
                BundleIdAllowlist = new[] { SyntheticBundleId },
                RequireProduction = requireProduction,
                PinnedRootCertificates = Chain.PinnedRoots,
            };

        public AppleAttestationRequest Request() =>
            new AppleAttestationRequest(KeyId, AttestationObject, Challenge);

        public AppleAttestationRequest RequestWith(
            byte[] attestationObject,
            byte[]? challenge = null,
            byte[]? keyId = null) =>
            new AppleAttestationRequest(
                keyId ?? KeyId,
                attestationObject,
                challenge ?? Challenge);

        /// <summary>Rebuilds the object around different authenticator data.</summary>
        public byte[] ObjectWithAuthenticatorData(byte[] authenticatorData) =>
            CborBuilder.AttestationObject(
                AppleAppAttestVerifier.AttestationFormat,
                Chain.Der,
                CborBuilder.SampleReceipt,
                authenticatorData);

        public Task<AttestationResult> Verify(bool requireProduction, byte[]? challenge = null) =>
            new AppleAppAttestVerifier(Options(requireProduction))
                .VerifyAsync(RequestWith(AttestationObject, challenge), InsideSyntheticWindow);

        /// <summary>
        /// Assembles authenticator data in the attestation layout.
        /// </summary>
        /// <remarks>
        /// The credential public key is a placeholder. Nothing in this library reads it: the
        /// attested key is taken from the certificate, because a COSE key inside the
        /// authenticator data is the device's own claim while the certificate is Apple's
        /// signature.
        /// </remarks>
        private static byte[] BuildAuthenticatorData(
            byte[] rpIdHash,
            uint signCount,
            byte[] aaguid,
            byte[] credentialId)
        {
            byte[] placeholderPublicKey = Enumerable.Range(0, 16).Select(i => (byte)(0xC0 + i)).ToArray();
            byte[] data = new byte[37 + 16 + 2 + credentialId.Length + placeholderPublicKey.Length];

            rpIdHash.CopyTo(data, 0);
            data[32] = 0x40;
            BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(33, 4), signCount);
            aaguid.CopyTo(data, 37);
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(53, 2), (ushort)credentialId.Length);
            credentialId.CopyTo(data, 55);
            placeholderPublicKey.CopyTo(data, 55 + credentialId.Length);

            return data;
        }

        private static byte[] KeyIdOf(AsymmetricKeyParameter publicKey) =>
            Sha256(((ECPublicKeyParameters)publicKey).Q.Normalize().GetEncoded(compressed: false));

        private static byte[] KeyIdOf(X509Certificate certificate) =>
            KeyIdOf(certificate.GetPublicKey());
    }

    /// <summary>
    /// The device vector, with every expected value derived from the vector itself.
    /// </summary>
    private sealed class VectorInputs
    {
        private VectorInputs(AppleVectorFile vector, X509Certificate appleRoot)
        {
            Vector = vector;
            AppleRoot = appleRoot;
        }

        public AppleVectorFile Vector { get; }

        /// <summary>
        /// Apple's published App Attest root -- a genuine platform root, not an intermediate
        /// the device sent. The intermediate below it travels inside the object's own
        /// <c>x5c</c>, so this is the whole of what a caller supplies.
        /// </summary>
        public X509Certificate AppleRoot { get; }

        public byte[] KeyId => Convert.FromBase64String(Vector.KeyIdBase64);

        public byte[] Challenge => Vector.AttestationChallenge;

        /// <summary>The credential certificate, read out of the object the device sent.</summary>
        public X509Certificate CredentialCertificate
        {
            get
            {
                Assert.True(
                    new AppleCborReader().TryReadAttestationObject(
                        Vector.AttestationObject,
                        out AppleAttestationObject? attestation),
                    "the vector's attestation object did not decode");

                return new X509CertificateParser().ReadCertificate(attestation!.X5c[0].ToArray());
            }
        }

        public static VectorInputs Load() =>
            new VectorInputs(
                AppleVectorFile.Load(),
                PemRootStore.LoadFromPem(File.ReadAllText(TestVectors.Resolve(TestVectors.AppleRootPath)))[0]);

        public AppleAttestOptions Options(
            string? teamId = null,
            IReadOnlyCollection<string>? bundleIds = null,
            IReadOnlyList<X509Certificate>? roots = null) =>
            new AppleAttestOptions
            {
                TeamId = teamId ?? Vector.TeamId,
                BundleIdAllowlist = bundleIds ?? new[] { Vector.BundleId },

                // The vector is a development capture, so the accepting path has to say so
                // explicitly. The default is exercised on its own in the AC-8 test.
                RequireProduction = false,
                PinnedRootCertificates = roots ?? new[] { AppleRoot },
            };

        public AppleAttestationRequest Request(byte[]? keyId = null, byte[]? challenge = null) =>
            new AppleAttestationRequest(
                keyId ?? KeyId,
                Vector.AttestationObject,
                challenge ?? Challenge);

        public Task<AttestationResult> Verify(
            string? teamId = null,
            IReadOnlyCollection<string>? bundleIds = null,
            IReadOnlyList<X509Certificate>? roots = null,
            byte[]? keyId = null,
            byte[]? challenge = null,
            DateTimeOffset? evaluationTime = null) =>
            new AppleAppAttestVerifier(Options(teamId, bundleIds, roots))
                .VerifyAsync(Request(keyId, challenge), evaluationTime ?? InsideVectorWindow);
    }
}
