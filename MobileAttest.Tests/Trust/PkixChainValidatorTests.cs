using System.Text;
using MobileAttest.Abstractions;
using MobileAttest.Tests.TestSupport;
using MobileAttest.Trust;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.Trust;

/// <summary>
/// Exercises the chain engine in both directions.
/// </summary>
/// <remarks>
/// <para>
/// The synthetic tests generate their own hierarchy, so they run on any machine and carry
/// nothing that could be committed by accident. They prove the engine: a chain reaching
/// its own root is accepted, the same chain against a stranger's root is refused, a
/// tampered certificate is caught, and the clock is genuinely read.
/// </para>
/// <para>
/// The two vector tests prove the engine also works on real device material. They anchor
/// at the highest certificate the vector actually contains, which is an intermediate.
/// <b>They do not prove that a real chain reaches a real Google root</b>: the certificate
/// above this anchor, and the root above that, are not in the vector and not in this
/// repository. That claim is not made here or anywhere else in this project.
/// </para>
/// </remarks>
public class PkixChainValidatorTests
{
    // All three paths live on the shared locator now that a second test class needs them.
    private const string AndroidIntermediatePath = TestVectors.AndroidIntermediatePath;
    private const string AndroidAnchorPath = TestVectors.AndroidAnchorPath;

    /// <summary>An instant inside the window <see cref="TestChainBuilder"/> gives by default.</summary>
    private static FixedTimeProvider InsideDefaultWindow => FixedTimeProvider.AtUtc(2026, 6, 1);

    [Fact]
    public void AC4_Chain_ValidToPinnedRoot_IsAccepted()
    {
        TestChain chain = TestChainBuilder.Create();
        PkixChainValidator validator = new PkixChainValidator(InsideDefaultWindow);

        ChainValidationResult result = validator.Validate(chain.Der, chain.PinnedRoots);

        Assert.True(result.IsValid, $"expected the chain to validate, got {result.Reason}");
        Assert.Equal(AttestationFailureReason.None, result.Reason);

        // The anchor is reported, so a caller can tell which of several pinned roots the
        // device actually reached rather than only that one of them was reached.
        Assert.Equal(chain.Root, result.TrustAnchor);

        // The decoded chain comes back, so a verifier reads the leaf this validator
        // checked instead of decoding the same bytes again.
        Assert.Equal(2, result.ValidatedPath.Count);
        Assert.Equal(chain.Leaf, result.ValidatedPath[0]);
    }

    [Fact]
    public void AC5_Chain_ValidButRootNotPinned_ReturnsRootNotPinned()
    {
        TestChain chain = TestChainBuilder.Create();
        TestChain stranger = TestChainBuilder.Create("Unrelated Authority");
        PkixChainValidator validator = new PkixChainValidator(InsideDefaultWindow);

        // The chain is internally sound and carries its own root's name. Soundness is not
        // the question: a device that mints its own hierarchy produces exactly this, and
        // the only thing standing between it and acceptance is the anchor set.
        ChainValidationResult result = validator.Validate(chain.Der, stranger.PinnedRoots);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.RootNotPinned, result.Reason);
        Assert.Null(result.TrustAnchor);
        Assert.Empty(result.ValidatedPath);
    }

    [Fact]
    public void AC5_RootNotPinned_IsDistinctFromChainInvalid()
    {
        TestChain chain = TestChainBuilder.Create();
        TestChain stranger = TestChainBuilder.Create("Unrelated Authority");
        PkixChainValidator validator = new PkixChainValidator(InsideDefaultWindow);

        ChainValidationResult notPinned = validator.Validate(chain.Der, stranger.PinnedRoots);
        ChainValidationResult broken = validator.Validate(chain.DerWithTamperedIntermediate, chain.PinnedRoots);

        // Two different faults. "We never agreed to trust this authority" and "this chain
        // does not hold together" send an operator to different places, and the underlying
        // library reports both through one exception type -- so if they were not separated
        // here they would arrive as one reason and the distinction would be lost.
        Assert.Equal(AttestationFailureReason.RootNotPinned, notPinned.Reason);
        Assert.Equal(AttestationFailureReason.CertificateChainInvalid, broken.Reason);
        Assert.NotEqual(notPinned.Reason, broken.Reason);
    }

    [Fact]
    public void AC6_Chain_ClockInsideValidityWindow_IsAccepted()
    {
        TestChain chain = TestChainBuilder.Create();

        ChainValidationResult result = new PkixChainValidator(InsideDefaultWindow)
            .Validate(chain.Der, chain.PinnedRoots);

        Assert.True(result.IsValid, $"expected the chain to validate, got {result.Reason}");
    }

    [Fact]
    public void AC6_Chain_ClockAfterValidityWindow_ReturnsCertificateExpired()
    {
        TestChain chain = TestChainBuilder.Create();

        // The same chain as the test above. Only the clock moves, which is what makes the
        // clock the thing being tested.
        FixedTimeProvider afterExpiry = new FixedTimeProvider(
            new DateTimeOffset(chain.NotAfter.AddDays(1), TimeSpan.Zero));

        ChainValidationResult result = new PkixChainValidator(afterExpiry)
            .Validate(chain.Der, chain.PinnedRoots);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.CertificateExpired, result.Reason);
    }

    [Fact]
    public void AC6_Chain_ClockBeforeValidityWindow_ReturnsCertificateExpired()
    {
        TestChain chain = TestChainBuilder.Create();

        FixedTimeProvider beforeIssue = new FixedTimeProvider(
            new DateTimeOffset(chain.NotBefore.AddDays(-1), TimeSpan.Zero));

        // A certificate that has not come into force is as unusable as one that has left
        // it, and a clock set backwards is the cheapest way to reach that state.
        ChainValidationResult result = new PkixChainValidator(beforeIssue)
            .Validate(chain.Der, chain.PinnedRoots);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.CertificateExpired, result.Reason);
    }

    [Fact]
    public void AC7_Chain_TamperedIntermediate_ReturnsChainInvalid()
    {
        TestChain chain = TestChainBuilder.Create();
        IReadOnlyList<byte[]> tampered = chain.DerWithTamperedIntermediate;

        // The flipped byte is inside the signature, so the certificate still decodes and
        // still claims the same issuer. Everything structural about the chain still lines
        // up; only the mathematics does not.
        X509Certificate decoded = new X509CertificateParser().ReadCertificate(tampered[1]);
        Assert.Equal(chain.Intermediate.SubjectDN, decoded.SubjectDN);
        Assert.Equal(chain.Intermediate.IssuerDN, decoded.IssuerDN);

        ChainValidationResult result = new PkixChainValidator(InsideDefaultWindow)
            .Validate(tampered, chain.PinnedRoots);

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.CertificateChainInvalid, result.Reason);
    }

    [Fact]
    public void AC9_Chain_ExceedsMaxLength_IsRejectedWithoutParsing()
    {
        // A chain that is both too long and long expired. The two faults answer with
        // different reasons, so the reason that comes back says which check ran first.
        TestChain expired = TestChainBuilder.Create(
            notBefore: new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            notAfter: new DateTime(2021, 1, 1, 0, 0, 0, DateTimeKind.Utc));

        FixedTimeProvider longAfterExpiry = FixedTimeProvider.AtUtc(2026, 6, 1);

        ChainValidationResult withRoom = new PkixChainValidator(
                longAfterExpiry,
                new ChainValidationPolicy { MaxChainLength = 10 })
            .Validate(expired.Der, expired.PinnedRoots);

        // Room for the chain: it is decoded, its dates are read, and expiry is the answer.
        Assert.Equal(AttestationFailureReason.CertificateExpired, withRoom.Reason);

        ChainValidationResult overLimit = new PkixChainValidator(
                longAfterExpiry,
                new ChainValidationPolicy { MaxChainLength = 1 })
            .Validate(expired.Der, expired.PinnedRoots);

        // Same bytes, same clock, lower ceiling. The answer changes to the length fault,
        // which it could not do if the certificates had been decoded and dated first.
        Assert.False(overLimit.IsValid);
        Assert.Equal(AttestationFailureReason.CertificateChainInvalid, overLimit.Reason);

        // And the ceiling is a ceiling, not a smaller limit off by one: a chain of exactly
        // the permitted length still validates.
        TestChain current = TestChainBuilder.Create();
        ChainValidationResult atLimit = new PkixChainValidator(
                InsideDefaultWindow,
                new ChainValidationPolicy { MaxChainLength = 2 })
            .Validate(current.Der, current.PinnedRoots);

        Assert.True(atLimit.IsValid, $"expected a chain at the limit to validate, got {atLimit.Reason}");
    }

    [Fact]
    public void AC10_Chain_MalformedInputs_ReturnReasonNotException()
    {
        TestChain chain = TestChainBuilder.Create();
        TestChain stranger = TestChainBuilder.Create("Unrelated Authority");
        PkixChainValidator validator = new PkixChainValidator(InsideDefaultWindow);

        // Every one of these is something an attacker can put on the wire. None of them
        // may reach the caller as an exception: a verifier that throws on hostile input
        // turns a rejection into an outage.
        (string Description, IReadOnlyList<byte[]> Chain)[] cases =
        {
            ("no chain at all", null!),
            ("an empty chain", Array.Empty<byte[]>()),
            ("a single null element", new byte[][] { null! }),
            ("a null after a good certificate", new[] { chain.Leaf.GetEncoded(), null! }),
            ("a zero-length element", new[] { Array.Empty<byte>() }),
            ("text instead of DER", new[] { Encoding.ASCII.GetBytes("not a certificate at all") }),
            ("a sequence that is not a certificate", new[] { new byte[] { 0x30, 0x03, 0x01, 0x02, 0x03 } }),
            ("a truncated sequence", new[] { new byte[] { 0x30, 0x82, 0x01, 0x00 } }),
            ("a declared length far past the input", new[] { new byte[] { 0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF } }),
            ("a lone self-signed certificate", new[] { chain.Root.GetEncoded() }),
        };

        foreach ((string description, IReadOnlyList<byte[]> malformed) in cases)
        {
            ChainValidationResult? result = null;
            Exception? thrown = Record.Exception(() => result = validator.Validate(malformed, stranger.PinnedRoots));

            Assert.True(thrown is null, $"validating {description} threw {thrown?.GetType().Name}: {thrown?.Message}");
            Assert.NotNull(result);
            Assert.False(result!.IsValid, $"validating {description} was accepted");

            // A rejection with no reason reads as a success in every log and comparison
            // downstream, so the reason being present is part of the contract.
            Assert.NotEqual(AttestationFailureReason.None, result.Reason);
            Assert.Null(result.TrustAnchor);
        }
    }

    [Fact]
    public void AC8_Validator_DoesNotEnableRevocationChecking()
    {
        TestChain chain = TestChainBuilder.Create();

        ChainValidationResult result = new PkixChainValidator(InsideDefaultWindow)
            .Validate(chain.Der, chain.PinnedRoots);

        Assert.True(result.IsValid, $"expected the chain to validate, got {result.Reason}");

        // On its own that proves nothing, because a chain with no revocation information
        // might pass either way. The control below shows it does not: the library turns
        // revocation on by default, and with it on this very chain is refused for want of
        // a revocation list. So the acceptance above is evidence the setting was changed.
        HashSet<TrustAnchor> anchors = new HashSet<TrustAnchor> { new TrustAnchor(chain.Root, null) };
        Assert.True(new PkixParameters(anchors).IsRevocationEnabled);

        PkixParameters revocationOn = new PkixParameters(anchors)
        {
            IsRevocationEnabled = true,
            Date = new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc),
        };

        Exception? refused = Record.Exception(() => new PkixCertPathValidator().Validate(
            new PkixCertPath(new List<X509Certificate> { chain.Leaf, chain.Intermediate }),
            revocationOn));

        Assert.IsType<PkixCertPathValidatorException>(refused);
        Assert.Contains("CRL", refused!.Message);
    }

    [Fact]
    public void AC16_Chain_EmptyTrustAnchorSet_ReturnsRootNotPinned()
    {
        TestChain chain = TestChainBuilder.Create();
        PkixChainValidator validator = new PkixChainValidator(InsideDefaultWindow);

        // The chain here is perfectly good. That is the whole point: with nothing to pin
        // it to there is no such thing as a chain good enough to pass, and "no root
        // configured" must never come back as "nothing objected".
        IReadOnlyList<X509Certificate>[] anchorSets =
        {
            null!,
            Array.Empty<X509Certificate>(),
            new X509Certificate[] { null! },
        };

        foreach (IReadOnlyList<X509Certificate> anchors in anchorSets)
        {
            ChainValidationResult result = validator.Validate(chain.Der, anchors);

            Assert.False(result.IsValid);
            Assert.Equal(AttestationFailureReason.RootNotPinned, result.Reason);
        }
    }

    [FixtureFact(TestVectors.AndroidLeafPath, AndroidIntermediatePath, AndroidAnchorPath)]
    public void AC4_RealAndroidChain_AnchoredAtSuppliedIntermediate_IsAccepted()
    {
        X509Certificate leaf = LoadAndroidCertificate(TestVectors.AndroidLeafPath);
        X509Certificate intermediate = LoadAndroidCertificate(AndroidIntermediatePath);
        X509Certificate anchor = LoadAndroidCertificate(AndroidAnchorPath);

        // Measured: the intermediate is valid from 2026-09-02 to 2026-09-14. The clock is
        // pinned inside that window, not read from the machine, so this test asserts the
        // same thing next year as it does today.
        PkixChainValidator validator = new PkixChainValidator(FixedTimeProvider.AtUtc(2026, 9, 5, 12));

        ChainValidationResult result = validator.Validate(
            new[] { leaf.GetEncoded(), intermediate.GetEncoded() },
            new[] { anchor });

        Assert.True(result.IsValid, $"expected the device chain to validate, got {result.Reason}");
        Assert.Equal(anchor, result.TrustAnchor);
        Assert.Equal(2, result.ValidatedPath.Count);

        // What this shows is that the engine works on real device material: a chain that
        // reaches the anchor it was given is accepted. The anchor is an intermediate the
        // device itself sent, not a platform root -- the certificate above it is not in
        // the vector, so a genuine root-of-trust claim cannot be, and is not, made here.
        Assert.NotEqual(anchor.SubjectDN, anchor.IssuerDN);
    }

    [FixtureFact(TestVectors.AndroidLeafPath, AndroidIntermediatePath, AndroidAnchorPath)]
    public void AC6_RealAndroidChain_ClockAfterIntermediateExpiry_ReturnsCertificateExpired()
    {
        X509Certificate leaf = LoadAndroidCertificate(TestVectors.AndroidLeafPath);
        X509Certificate intermediate = LoadAndroidCertificate(AndroidIntermediatePath);
        X509Certificate anchor = LoadAndroidCertificate(AndroidAnchorPath);

        // The intermediate expires on 2026-09-14. Left to the machine clock, the test
        // above would begin failing on that date and would look like a defect in the
        // validator. Here the expiry is the assertion instead of the accident.
        PkixChainValidator validator = new PkixChainValidator(FixedTimeProvider.AtUtc(2026, 9, 15));

        ChainValidationResult result = validator.Validate(
            new[] { leaf.GetEncoded(), intermediate.GetEncoded() },
            new[] { anchor });

        Assert.False(result.IsValid);
        Assert.Equal(AttestationFailureReason.CertificateExpired, result.Reason);
    }

    private static X509Certificate LoadAndroidCertificate(string relativePath) =>
        PemRootStore.LoadFromPem(File.ReadAllText(TestVectors.Resolve(relativePath)))[0];
}
