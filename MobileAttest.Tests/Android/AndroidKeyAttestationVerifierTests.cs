using System.Text;
using MobileAttest.Abstractions;
using MobileAttest.Android;
using MobileAttest.Tests.TestSupport;
using MobileAttest.Trust;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.Android;

/// <summary>
/// Exercises the whole Android path: chain, extension, policy, result.
/// </summary>
/// <remarks>
/// <para>
/// The tests that need no vector run on any machine and prove the joins -- that hostile input
/// comes back as a reason, that a leaf without the extension is told apart from one whose
/// extension will not parse, and that a verifier with no pinned root refuses instead of
/// falling back to something.
/// </para>
/// <para>
/// The vector tests prove the same code on real device material, with every input derived
/// from the vector itself: the challenge and the signing digest are read out of the record
/// rather than written here, so nothing from a real device enters this repository.
/// </para>
/// <para>
/// <b>What none of them prove:</b> that a device chain reaches a genuine Google hardware
/// attestation root. The certificate above the anchor used here was never supplied, so the
/// anchor is an intermediate the device itself sent. The chain engine, the parser and the
/// policy are shown to work on real material; the trust root is not.
/// </para>
/// </remarks>
public class AndroidKeyAttestationVerifierTests
{
    /// <summary>
    /// An instant inside the window the vector's intermediate is valid over, which is
    /// 2026-09-02 to 2026-09-14.
    /// </summary>
    private static FixedTimeProvider InsideVectorWindow => FixedTimeProvider.AtUtc(2026, 9, 5, 12);

    /// <summary>An instant inside the window <see cref="TestChainBuilder"/> gives by default.</summary>
    private static FixedTimeProvider InsideSyntheticWindow => FixedTimeProvider.AtUtc(2026, 6, 1);

    [Fact]
    public async Task AC13_Verifier_MalformedInputs_ReturnResultNotException()
    {
        TestChain chain = TestChainBuilder.Create();
        TestChain notDer = TestChainWithExtension(Encoding.ASCII.GetBytes("not a KeyDescription"));
        TestChain wrongShape = TestChainWithExtension(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x05 });

        // Each hierarchy is generated with its own root, so all three are pinned. Otherwise
        // the two malformed-extension cases would be refused at the chain step and would
        // never reach the parser they exist to exercise -- passing this test while proving
        // nothing about the extension at all.
        AndroidAttestOptions options = new AndroidAttestOptions
        {
            AllowedSignatureDigests = new[] { Convert.ToHexString(SyntheticDigest) },
            PinnedRootCertificates = new[] { chain.Root, notDer.Root, wrongShape.Root },
        };

        AndroidKeyAttestationVerifier verifier =
            new AndroidKeyAttestationVerifier(options, InsideSyntheticWindow);

        // A null request is the one exception the contract declares, and it stays an
        // exception: it is a mistake in the calling code, not something a device can send.
        await Assert.ThrowsAsync<ArgumentNullException>(() => verifier.VerifyAsync(null!));

        // Everything below is something an attacker can put on the wire. None of it may reach
        // the caller as an exception: a verifier that throws on hostile input turns a
        // rejection into an outage.
        (string Description, AttestationRequest Request)[] cases =
        {
            (
                "a request from another platform",
                new AppleAttestationRequest(
                    ReadOnlyMemory<byte>.Empty,
                    ReadOnlyMemory<byte>.Empty,
                    SyntheticChallenge)
            ),
            (
                "an empty chain",
                Request(Array.Empty<byte[]>())
            ),
            (
                "a chain of one empty element",
                Request(new[] { Array.Empty<byte>() })
            ),
            (
                "text instead of DER",
                Request(new[] { Encoding.ASCII.GetBytes("not a certificate at all") })
            ),
            (
                "a declared length far past the input",
                Request(new[] { new byte[] { 0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF } })
            ),
            (
                "a chain that reaches no pinned root",
                Request(TestChainBuilder.Create("Unrelated Authority").Der)
            ),
            (
                "a leaf carrying no attestation extension",
                Request(chain.Der)
            ),
            (
                "a leaf whose attestation extension is not DER",
                Request(notDer.Der)
            ),
            (
                "a leaf whose attestation extension is DER of the wrong shape",
                Request(wrongShape.Der)
            ),
            (
                "a chain with no challenge to bind to",
                new AndroidAttestationRequest(
                    chain.Der.Select(der => (ReadOnlyMemory<byte>)der).ToArray(),
                    ReadOnlyMemory<byte>.Empty)
            ),
        };

        foreach ((string description, AttestationRequest request) in cases)
        {
            AttestationResult? result = null;
            Exception? thrown = await Record.ExceptionAsync(async () =>
                result = await verifier.VerifyAsync(request));

            Assert.True(
                thrown is null,
                $"verifying {description} threw {thrown?.GetType().Name}: {thrown?.Message}");

            Assert.NotNull(result);
            Assert.False(result!.IsValid, $"verifying {description} was accepted");

            // A rejection with no reason reads as a success in every log and comparison
            // downstream, so the reason being present is part of the contract.
            Assert.NotEqual(AttestationFailureReason.None, result.Reason);

            // A failed result carries no attested material, whatever went wrong.
            Assert.Null(result.AppId);
            Assert.True(result.KeyId.IsEmpty);
            Assert.True(result.PublicKeyDer.IsEmpty);

            // The platform is still named. A caller routing several verifiers must be able to
            // tell which one refused.
            Assert.Equal(Platform.Android, result.Platform);
        }

        // "No reason of any kind" is a weak assertion, so the two extension faults are named
        // here. A chain that validates and then carries an unreadable extension is a
        // different fault from one that carries none, and the loop above would have accepted
        // either answer for both.
        Assert.Equal(
            AttestationFailureReason.MalformedAttestationExtension,
            (await verifier.VerifyAsync(Request(notDer.Der))).Reason);

        Assert.Equal(
            AttestationFailureReason.MalformedAttestationExtension,
            (await verifier.VerifyAsync(Request(wrongShape.Der))).Reason);

        Assert.Equal(
            AttestationFailureReason.AttestationExtensionMissing,
            (await verifier.VerifyAsync(Request(chain.Der))).Reason);
    }

    [Fact]
    public async Task AC13_Verifier_LeafWithoutExtension_ReportsExtensionMissing()
    {
        TestChain chain = TestChainBuilder.Create();

        AndroidAttestOptions options = new AndroidAttestOptions
        {
            AllowedSignatureDigests = new[] { Convert.ToHexString(SyntheticDigest) },
            PinnedRootCertificates = chain.PinnedRoots,
        };

        AttestationResult result = await new AndroidKeyAttestationVerifier(options, InsideSyntheticWindow)
            .VerifyAsync(Request(chain.Der));

        // The chain here is sound and reaches its pinned root, so this is not a chain
        // failure. It is an ordinary key certificate presented where an attested one was
        // expected -- usually the wrong element of the chain, or a device that never
        // requested attestation -- and a caller can act on that without guessing.
        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.AttestationExtensionMissing, result.Reason);
        Assert.NotEqual(AttestationFailureReason.MalformedAttestationExtension, result.Reason);
    }

    [Fact]
    public async Task AC9_Verifier_NoPinnedRoots_ReturnsRootNotPinned()
    {
        TestChain chain = TestChainBuilder.Create();

        // Configured with everything except a root. This library ships none and downloads
        // none, so this is what a caller who never supplied one actually has.
        AndroidAttestOptions unpinned = new AndroidAttestOptions
        {
            AllowedSignatureDigests = new[] { Convert.ToHexString(SyntheticDigest) },
        };

        AttestationResult result = await new AndroidKeyAttestationVerifier(unpinned, InsideSyntheticWindow)
            .VerifyAsync(Request(chain.Der));

        // No default root, no silent pass. "Nothing to check against" is a refusal.
        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.RootNotPinned, result.Reason);

        AndroidAttestOptions pinned = new AndroidAttestOptions
        {
            AllowedSignatureDigests = unpinned.AllowedSignatureDigests,
            PinnedRootCertificates = chain.PinnedRoots,
        };

        AttestationResult reached = await new AndroidKeyAttestationVerifier(pinned, InsideSyntheticWindow)
            .VerifyAsync(Request(chain.Der));

        // The same request with the root supplied gets past the chain step and fails later,
        // for the leaf's missing extension. Without this control the refusal above could have
        // been about anything.
        Assert.Equal(AttestationFailureReason.AttestationExtensionMissing, reached.Reason);
    }

    [FixtureFact(TestVectors.AndroidLeafPath, TestVectors.AndroidIntermediatePath, TestVectors.AndroidAnchorPath)]
    public async Task AC4_RealDeviceChain_WithDerivedInputs_IsValid()
    {
        VectorInputs vector = VectorInputs.Load();

        AttestationResult result = await Verifier(vector, vector.SignatureDigestHex)
            .VerifyAsync(vector.Request(vector.Challenge));

        Assert.True(result.IsValid, $"expected the device attestation to verify, got {result.Reason}");
        Assert.Equal(AttestationFailureReason.None, result.Reason);
        Assert.Equal(Platform.Android, result.Platform);

        // Android carries no development or production marker of the kind Apple's AAGUID
        // gives, so nothing here is invented to fill the field.
        Assert.Equal(AttestationEnvironment.Unknown, result.Environment);

        // The identifier is over the SubjectPublicKeyInfo, not over the whole certificate.
        // Both are 32 bytes and both are stable, so only the inequality below distinguishes
        // them -- and a caller recomputing this identifier from the same certificate has to
        // land on the same value.
        byte[] expectedKeyId = Sha256(vector.Leaf.SubjectPublicKeyInfo.GetDerEncoded());

        Assert.Equal(expectedKeyId, result.KeyId.ToArray());
        Assert.NotEqual(Sha256(vector.Leaf.GetEncoded()), result.KeyId.ToArray());
        Assert.Equal(vector.Leaf.SubjectPublicKeyInfo.GetDerEncoded(), result.PublicKeyDer.ToArray());

        // The application identity is filled in, and it is filled in from the record rather
        // than from anything written here.
        Assert.False(string.IsNullOrEmpty(result.AppId));
        Assert.Equal(vector.PackageName, result.AppId);

        // Android key attestation carries neither a counter nor a receipt.
        Assert.Equal(0u, result.SignCount);
        Assert.True(result.Receipt.IsEmpty);

        // AC-7 against real device material. Measured: this device attests at
        // TrustedEnvironment, not StrongBox, so demanding StrongBox has to refuse it. The
        // request, the chain, the clock and the allowlist are the ones that just succeeded;
        // only the option changes, which is what makes the option the cause.
        Assert.Equal(SecurityLevel.TrustedEnvironment, vector.Record.AttestationSecurityLevel);

        AndroidAttestOptions strongBoxOnly = vector.Options(vector.SignatureDigestHex);
        strongBoxOnly.RequireStrongBox = true;

        AttestationResult refused = await new AndroidKeyAttestationVerifier(strongBoxOnly, InsideVectorWindow)
            .VerifyAsync(vector.Request(vector.Challenge));

        Assert.False(refused.IsValid);
        Assert.Equal(AttestationFailureReason.SecurityLevelInsufficient, refused.Reason);
    }

    [FixtureFact(TestVectors.AndroidLeafPath, TestVectors.AndroidIntermediatePath, TestVectors.AndroidAnchorPath)]
    public async Task AC5_RealDeviceChain_MutatedChallenge_ReturnsChallengeMismatch()
    {
        VectorInputs vector = VectorInputs.Load();

        byte[] mutated = vector.Challenge.ToArray();
        mutated[^1] ^= 0x01;

        AttestationResult result = await Verifier(vector, vector.SignatureDigestHex)
            .VerifyAsync(vector.Request(mutated));

        // One bit of the expected challenge. The accepting test derives its challenge from
        // the record, so on its own it would pass even if the comparison were never made;
        // this is the test that shows the comparison bites.
        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.ChallengeMismatch, result.Reason);
    }

    [FixtureFact(TestVectors.AndroidLeafPath, TestVectors.AndroidIntermediatePath, TestVectors.AndroidAnchorPath)]
    public async Task AC6_RealDeviceChain_DigestRemovedFromAllowlist_IsRejected()
    {
        VectorInputs vector = VectorInputs.Load();

        // A non-empty allowlist that does not contain this application. An empty one would
        // also refuse, but for a different reason, and would not show that the comparison ran.
        AttestationResult result = await Verifier(vector, Convert.ToHexString(SyntheticDigest))
            .VerifyAsync(vector.Request(vector.Challenge));

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.SignatureDigestNotAllowed, result.Reason);
    }

    [FixtureFact(TestVectors.AndroidLeafPath, TestVectors.AndroidIntermediatePath, TestVectors.AndroidAnchorPath)]
    public async Task AC8_RealDeviceChain_ClockAfterIntermediateExpiry_ReturnsCertificateExpired()
    {
        VectorInputs vector = VectorInputs.Load();

        AndroidAttestOptions options = vector.Options(vector.SignatureDigestHex);

        // Measured: the intermediate in this vector expires on 2026-09-14. Left to the
        // machine clock, every other test in this file would begin failing after that date
        // and would look like a defect here rather than an expired input. The clock is pinned
        // everywhere; here the expiry is the assertion instead of the accident.
        AttestationResult result = await new AndroidKeyAttestationVerifier(
                options,
                FixedTimeProvider.AtUtc(2026, 9, 20))
            .VerifyAsync(vector.Request(vector.Challenge));

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.CertificateExpired, result.Reason);
    }

    [FixtureFact(TestVectors.AndroidLeafPath, TestVectors.AndroidIntermediatePath, TestVectors.AndroidAnchorPath)]
    public async Task AC9_RealDeviceChain_ForeignAnchor_ReturnsRootNotPinned()
    {
        VectorInputs vector = VectorInputs.Load();

        AndroidAttestOptions options = vector.Options(vector.SignatureDigestHex);

        // A perfectly good authority that this chain has nothing to do with. Pinning is the
        // only thing standing between a device that mints its own hierarchy and acceptance,
        // so it has to bite on real material and not only on generated certificates.
        options.PinnedRootCertificates = TestChainBuilder.Create("Unrelated Authority").PinnedRoots;

        AttestationResult result = await new AndroidKeyAttestationVerifier(options, InsideVectorWindow)
            .VerifyAsync(vector.Request(vector.Challenge));

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.RootNotPinned, result.Reason);

        // And with no anchor at all, the same refusal rather than a fallback.
        options.PinnedRootCertificates = Array.Empty<X509Certificate>();

        AttestationResult unpinned = await new AndroidKeyAttestationVerifier(options, InsideVectorWindow)
            .VerifyAsync(vector.Request(vector.Challenge));

        Assert.Equal(AttestationFailureReason.RootNotPinned, unpinned.Reason);
    }

    private AndroidKeyAttestationVerifier Verifier(VectorInputs vector, string allowedDigestHex) =>
        new AndroidKeyAttestationVerifier(vector.Options(allowedDigestHex), InsideVectorWindow);

    /// <summary>A 32-byte digest that belongs to no application, for allowlists that must not match.</summary>
    private static byte[] SyntheticDigest =>
        Enumerable.Range(0, 32).Select(i => (byte)(0x80 + i)).ToArray();

    /// <summary>A challenge for the synthetic tests, which never reach the comparison.</summary>
    private static byte[] SyntheticChallenge =>
        Enumerable.Range(0, 32).Select(i => (byte)(i * 3)).ToArray();

    private static AndroidAttestationRequest Request(IReadOnlyList<byte[]> chain) =>
        new AndroidAttestationRequest(
            chain.Select(der => (ReadOnlyMemory<byte>)der).ToArray(),
            SyntheticChallenge);

    private static TestChain TestChainWithExtension(byte[] extensionOctets) =>
        TestChainBuilder.Create(leafKeyAttestationExtension: extensionOctets);

    private static byte[] Sha256(byte[] value)
    {
        Sha256Digest digest = new Sha256Digest();
        digest.BlockUpdate(value, 0, value.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }

    /// <summary>
    /// The device vector, with every input a test needs derived from the vector itself.
    /// </summary>
    /// <remarks>
    /// The challenge and the signing digest are read out of the record the device sent. A test
    /// that wrote them down instead would put a real application identity into this
    /// repository, and would stop being a test of the vector the moment the vector changed.
    /// </remarks>
    private sealed class VectorInputs
    {
        private VectorInputs(
            X509Certificate leaf,
            X509Certificate intermediate,
            X509Certificate anchor,
            KeyDescription record)
        {
            Leaf = leaf;
            Intermediate = intermediate;
            Anchor = anchor;
            Record = record;
        }

        public X509Certificate Leaf { get; }

        public X509Certificate Intermediate { get; }

        /// <summary>
        /// The highest certificate the vector contains -- an intermediate, not a platform
        /// root. Nothing here shows that a device chain reaches a genuine Google root.
        /// </summary>
        public X509Certificate Anchor { get; }

        public KeyDescription Record { get; }

        public byte[] Challenge => Record.AttestationChallenge.ToArray();

        public string SignatureDigestHex =>
            Convert.ToHexString(ApplicationId.SignatureDigests[0].ToArray());

        public string PackageName => ApplicationId.PackageInfos[0].PackageName;

        private AttestationApplicationId ApplicationId =>
            Record.SoftwareEnforced.AttestationApplicationId!;

        public static VectorInputs Load()
        {
            X509Certificate leaf = LoadCertificate(TestVectors.AndroidLeafPath);

            Assert.True(
                KeyDescription.TryReadFrom(leaf, out KeyDescription? record, out AttestationFailureReason reason),
                $"the vector's leaf did not yield a record: {reason}");

            // Measured, and the reason the policy reads this list and not the other one: the
            // application identity is in the software-enforced list on a real device. A test
            // that silently fell back to the hardware-enforced list would hide that.
            Assert.NotNull(record!.SoftwareEnforced.AttestationApplicationId);
            Assert.Null(record.HardwareEnforced.AttestationApplicationId);

            return new VectorInputs(
                leaf,
                LoadCertificate(TestVectors.AndroidIntermediatePath),
                LoadCertificate(TestVectors.AndroidAnchorPath),
                record);
        }

        public AndroidAttestOptions Options(string allowedDigestHex) =>
            new AndroidAttestOptions
            {
                AllowedSignatureDigests = new[] { allowedDigestHex },
                RequireStrongBox = false,
                PinnedRootCertificates = new[] { Anchor },

                // Stated, because there is no default and a configuration that omits this is
                // refused with RevocationStatusUnavailable before it can succeed. Skip is the
                // honest choice here: these tests are about the chain, the extension and the
                // policy, no status source is wired, and this says so rather than quietly
                // relying on revocation not being consulted. The revocation behaviour itself
                // is covered in KeyStatusTests, without a vector.
                RevocationPolicy = RevocationPolicy.Skip,
            };

        public AndroidAttestationRequest Request(ReadOnlyMemory<byte> expectedChallenge) =>
            new AndroidAttestationRequest(
                new ReadOnlyMemory<byte>[] { Leaf.GetEncoded(), Intermediate.GetEncoded() },
                expectedChallenge);

        private static X509Certificate LoadCertificate(string relativePath) =>
            PemRootStore.LoadFromPem(File.ReadAllText(TestVectors.Resolve(relativePath)))[0];
    }
}
