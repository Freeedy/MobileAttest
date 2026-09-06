using System.Reflection;
using MobileAttest.Abstractions;
using MobileAttest.Android;
using MobileAttest.Tests.TestSupport;
using MobileAttest.Trust;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.Android;

/// <summary>
/// Structure, boundary and provenance tests for the Android key attestation parser.
/// </summary>
/// <remarks>
/// <para>
/// Most of these build their own input, so the parser's behaviour is covered on a clean
/// clone with no device vector present. The three marked
/// <see cref="FixtureFactAttribute"/> run the real device bytes through it, because the
/// arrangement this parser is built around -- the application identity living in the
/// software-enforced list -- was found by measuring a device and contradicts the written
/// specification the library was commissioned from.
/// </para>
/// </remarks>
public class KeyDescriptionTests
{
    private const int UnknownTagNumber = 9999;

    // ---------------------------------------------------------------------------------
    // Synthetic input. No device vector required.
    // ---------------------------------------------------------------------------------

    [Fact]
    public void AC5_KeyDescription_WellFormed_ParsesAllTopLevelFields()
    {
        KeyDescriptionBuilder builder = KeyDescriptionBuilder.RealisticLayout();
        builder.AttestationVersion = 300;
        builder.AttestationSecurityLevel = 1;
        builder.KeymasterVersion = 300;
        builder.KeymasterSecurityLevel = 2;

        Assert.True(KeyDescription.TryParse(builder.Build(), out KeyDescription? description));
        Assert.NotNull(description);

        Assert.Equal(300, description!.AttestationVersion);
        Assert.Equal(SecurityLevel.TrustedEnvironment, description.AttestationSecurityLevel);
        Assert.Equal(300, description.KeymasterVersion);
        Assert.Equal(SecurityLevel.StrongBox, description.KeymasterSecurityLevel);
        Assert.Equal(builder.AttestationChallenge, description.AttestationChallenge.ToArray());
        Assert.True(description.UniqueId.IsEmpty);
        Assert.NotNull(description.SoftwareEnforced);
        Assert.NotNull(description.HardwareEnforced);

        // Field order is what a shifted parser gets wrong while still returning true. The
        // two security levels are deliberately given different values above so that reading
        // one in place of the other cannot pass.
        Assert.NotEqual(description.AttestationSecurityLevel, description.KeymasterSecurityLevel);
    }

    [Fact]
    public void AC4_KeyDescription_SoftwareAndHardwareLists_AreKeptSeparate()
    {
        KeyDescriptionBuilder builder = KeyDescriptionBuilder.RealisticLayout();

        Assert.True(KeyDescription.TryParse(builder.Build(), out KeyDescription? description));
        Assert.NotNull(description);

        // Each list knows which one it is, so a list handed to a policy check on its own
        // still says how much it is worth.
        Assert.Equal(AuthorizationListSource.SoftwareEnforced, description!.SoftwareEnforced.Source);
        Assert.Equal(AuthorizationListSource.HardwareEnforced, description.HardwareEnforced.Source);

        // The arrangement measured on a real device: application identity on the software
        // side, origin and root of trust on the hardware side. Neither leaks into the other.
        Assert.NotNull(description.SoftwareEnforced.AttestationApplicationId);
        Assert.Null(description.HardwareEnforced.AttestationApplicationId);
        Assert.NotNull(description.HardwareEnforced.Origin);
        Assert.Null(description.SoftwareEnforced.Origin);
        Assert.NotNull(description.HardwareEnforced.RootOfTrust);
        Assert.Null(description.SoftwareEnforced.RootOfTrust);

        // There is no flattened view, and the application identity cannot be reached
        // without first choosing a list. This is asserted against the type rather than
        // against an instance: a convenience property added later would restore exactly the
        // confusion this separation exists to prevent, and would do it silently.
        Assert.Null(typeof(KeyDescription).GetProperty("AttestationApplicationId"));
        Assert.NotNull(typeof(AuthorizationList).GetProperty("AttestationApplicationId"));

        string[] listProperties = typeof(KeyDescription)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => property.PropertyType == typeof(AuthorizationList))
            .Select(property => property.Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[] { "HardwareEnforced", "SoftwareEnforced" }, listProperties);
    }

    [Fact]
    public void AC7_AuthorizationList_UnknownTag_IsSkippedNotFatal()
    {
        KeyDescriptionBuilder builder = KeyDescriptionBuilder.RealisticLayout();
        builder.HardwareEnforced.LeadingElements.Add(
            Der.ContextSpecific(UnknownTagNumber, Der.Integer(42)));

        Assert.True(KeyDescription.TryParse(builder.Build(), out KeyDescription? description));
        Assert.NotNull(description);

        // Android adds tags with new releases. Rejecting one would break this library on
        // the next Android version, so the tag is skipped -- but it is recorded, because a
        // field the device sent and the library ignored must leave a trace somewhere.
        Assert.Contains(UnknownTagNumber, description!.HardwareEnforced.UnknownTags);
        Assert.Empty(description.SoftwareEnforced.UnknownTags);

        // Everything after the unrecognised tag still parsed, which is the part that proves
        // the reader kept its position rather than merely surviving.
        Assert.Equal(KeyOrigin.Generated, description.HardwareEnforced.Origin);
        Assert.NotNull(description.HardwareEnforced.RootOfTrust);
        Assert.Equal(256, description.HardwareEnforced.KeySize);
        Assert.Equal(20260705, description.HardwareEnforced.BootPatchLevel);
    }

    [Fact]
    public void AC8_KeyDescription_TruncatedSequence_IsRejected()
    {
        byte[] complete = KeyDescriptionBuilder.RealisticLayout().Build();

        Assert.True(KeyDescription.TryParse(complete, out _));

        // Cut inside the contents: the outer header still declares the full length.
        AssertRejectedWithoutThrowing(complete.AsSpan(0, complete.Length - 20).ToArray());

        // Cut inside the header itself.
        AssertRejectedWithoutThrowing(complete.AsSpan(0, 1).ToArray());

        // Cut so that the software-enforced list is the last thing present.
        AssertRejectedWithoutThrowing(complete.AsSpan(0, complete.Length / 2).ToArray());
    }

    [Fact]
    public void AC8_KeyDescription_DeclaredLengthExceedsBuffer_IsRejected()
    {
        KeyDescriptionBuilder builder = KeyDescriptionBuilder.RealisticLayout();

        // The challenge announces 32767 bytes and carries 32. Nothing may be allocated or
        // sliced on that number before it has been measured against what actually arrived.
        builder.DeclaredChallengeLength = 0x7FFF;

        AssertRejectedWithoutThrowing(builder.Build());
    }

    [Fact]
    public void AC8_KeyDescription_WrongTagClass_IsRejected()
    {
        // A SET where the record must be a SEQUENCE.
        byte[] asSet = KeyDescriptionBuilder.RealisticLayout().Build();
        asSet[0] = Der.SetTag;
        AssertRejectedWithoutThrowing(asSet);

        // A universal tag inside an authorisation list. Every field of a list is
        // context-specific, so this is not a tag the library has yet to learn about -- it
        // is a structure that does not match the schema, and treating it as an unknown
        // field would let anything at all ride inside a list.
        KeyDescriptionBuilder universalInList = KeyDescriptionBuilder.RealisticLayout();
        universalInList.HardwareEnforced.LeadingElements.Add(Der.Integer(1));
        AssertRejectedWithoutThrowing(universalInList.Build());

        // A known field carried by a primitive context-specific tag, where the schema tags
        // explicitly and therefore requires a constructed wrapper. The tag has to be one
        // the parser knows -- an unrecognised tag is skipped whatever form it takes, which
        // is the intended behaviour and would hide this check.
        KeyDescriptionBuilder primitiveField = KeyDescriptionBuilder.RealisticLayout();
        primitiveField.HardwareEnforced.LeadingElements.Add(
            Der.Concat(
                Der.TagBytes(0x80, 704, constructed: false),
                Der.LengthBytes(1),
                new byte[] { 0x00 }));
        AssertRejectedWithoutThrowing(primitiveField.Build());
    }

    [Fact]
    public void AC8_KeyDescription_DeeplyNested_IsRejectedWithoutStackOverflow()
    {
        // 512 levels. The parser has no recursion in it: every read sits at a depth the
        // schema fixes, so nesting does not walk the stack down, it simply fails at the
        // first field whose type does not match.
        byte[] nested = Der.Null();

        for (int level = 0; level < 512; level++)
        {
            nested = Der.Sequence(nested);
        }

        AssertRejectedWithoutThrowing(nested);

        // The same input where an authorisation list is expected, so the rejection is
        // proven on the inner path as well as the outer one.
        KeyDescriptionBuilder builder = KeyDescriptionBuilder.RealisticLayout();
        builder.SoftwareEnforced.LeadingElements.Add(nested);
        AssertRejectedWithoutThrowing(builder.Build());
    }

    [Fact]
    public void AC8_KeyDescription_EmptyInput_IsRejected()
    {
        AssertRejectedWithoutThrowing(Array.Empty<byte>());
        AssertRejectedWithoutThrowing(new byte[] { Der.SequenceTag });
        AssertRejectedWithoutThrowing(new byte[] { Der.SequenceTag, 0x00 });
    }

    [Fact]
    public void AC10_RootOfTrust_NonCanonicalBoolean_IsRejected()
    {
        // DER encodes true as 0xFF and false as 0x00, and nothing else. Under BER any
        // non-zero byte reads as true, so a lenient parser would report a device as locked
        // on an encoding no genuine device produces.
        KeyDescriptionBuilder nonCanonical = KeyDescriptionBuilder.RealisticLayout();
        nonCanonical.HardwareEnforced.RootOfTrust!.DeviceLockedContentByte = 0x01;
        AssertRejectedWithoutThrowing(nonCanonical.Build());

        // Both canonical encodings are accepted and read for what they say, which is what
        // makes the rejection above a rule about encoding rather than a rule about true.
        KeyDescriptionBuilder locked = KeyDescriptionBuilder.RealisticLayout();
        locked.HardwareEnforced.RootOfTrust!.DeviceLockedContentByte = 0xFF;
        Assert.True(KeyDescription.TryParse(locked.Build(), out KeyDescription? lockedDescription));
        Assert.True(lockedDescription!.HardwareEnforced.RootOfTrust!.DeviceLocked);

        KeyDescriptionBuilder unlocked = KeyDescriptionBuilder.RealisticLayout();
        unlocked.HardwareEnforced.RootOfTrust!.DeviceLockedContentByte = 0x00;
        Assert.True(KeyDescription.TryParse(unlocked.Build(), out KeyDescription? unlockedDescription));
        Assert.False(unlockedDescription!.HardwareEnforced.RootOfTrust!.DeviceLocked);
    }

    [Fact]
    public void AC5_RootOfTrust_AllFourFields_AreParsed()
    {
        byte[] bootKey = Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + (i % 16))).ToArray();
        byte[] bootHash = Enumerable.Range(0, 32).Select(i => (byte)(0x50 + (i % 16))).ToArray();

        KeyDescriptionBuilder builder = KeyDescriptionBuilder.RealisticLayout();
        builder.HardwareEnforced.RootOfTrust = new RootOfTrustBuilder
        {
            VerifiedBootKey = bootKey,
            DeviceLockedContentByte = 0xFF,
            VerifiedBootState = (long)VerifiedBootState.Unverified,
            VerifiedBootHash = bootHash,
        };

        Assert.True(KeyDescription.TryParse(builder.Build(), out KeyDescription? description));

        RootOfTrust rootOfTrust = description!.HardwareEnforced.RootOfTrust!;
        Assert.Equal(bootKey, rootOfTrust.VerifiedBootKey.ToArray());
        Assert.True(rootOfTrust.DeviceLocked);
        Assert.Equal(VerifiedBootState.Unverified, rootOfTrust.VerifiedBootState);
        Assert.Equal(bootHash, rootOfTrust.VerifiedBootHash.ToArray());
        Assert.True(rootOfTrust.HasVerifiedBootHash);

        // The hash is optional in the schema. An older device that omits it produces a
        // record that is not malformed, and the absence has to stay distinguishable from a
        // hash of zero length.
        KeyDescriptionBuilder withoutHash = KeyDescriptionBuilder.RealisticLayout();
        withoutHash.HardwareEnforced.RootOfTrust!.VerifiedBootHash = null;

        Assert.True(KeyDescription.TryParse(withoutHash.Build(), out KeyDescription? olderDevice));
        Assert.False(olderDevice!.HardwareEnforced.RootOfTrust!.HasVerifiedBootHash);
        Assert.True(olderDevice.HardwareEnforced.RootOfTrust.VerifiedBootHash.IsEmpty);
    }

    [Fact]
    public void AC5_AttestationApplicationId_MultipleDigests_AreAllParsed()
    {
        byte[][] digests = new[]
        {
            Enumerable.Repeat((byte)0x11, 32).ToArray(),
            Enumerable.Repeat((byte)0x22, 32).ToArray(),
            Enumerable.Repeat((byte)0x33, 32).ToArray(),
        };

        KeyDescriptionBuilder builder = KeyDescriptionBuilder.RealisticLayout();
        builder.SoftwareEnforced.AttestationApplicationId =
            KeyDescriptionBuilder.EncodeAttestationApplicationId(
                new[] { ("com.example.first", 10L), ("com.example.second", 20L) },
                digests);

        Assert.True(KeyDescription.TryParse(builder.Build(), out KeyDescription? description));

        AttestationApplicationId applicationId =
            description!.SoftwareEnforced.AttestationApplicationId!;

        Assert.Equal(2, applicationId.PackageInfos.Count);
        Assert.Equal("com.example.first", applicationId.PackageInfos[0].PackageName);
        Assert.Equal(10L, applicationId.PackageInfos[0].Version);
        Assert.Equal("com.example.second", applicationId.PackageInfos[1].PackageName);
        Assert.Equal(20L, applicationId.PackageInfos[1].Version);

        // An application signed by more than one certificate carries more than one digest.
        // Keeping only the first would silently narrow an allowlist check to one key.
        Assert.Equal(3, applicationId.SignatureDigests.Count);
        Assert.Equal(digests[0], applicationId.SignatureDigests[0].ToArray());
        Assert.Equal(digests[1], applicationId.SignatureDigests[1].ToArray());
        Assert.Equal(digests[2], applicationId.SignatureDigests[2].ToArray());
    }

    [Fact]
    public void AC9_Extension_Absent_ReportsExtensionMissing()
    {
        X509Certificate certificate = BuildCertificate(extensionOctets: null);

        Assert.False(KeyDescription.TryReadFrom(
            certificate,
            out KeyDescription? description,
            out AttestationFailureReason reason));

        Assert.Null(description);
        Assert.Equal(AttestationFailureReason.AttestationExtensionMissing, reason);
    }

    [Fact]
    public void AC9_Extension_Malformed_ReportsMalformedExtension()
    {
        // Present, and not a KeyDescription. This is a device or an attacker sending
        // something; the certificate with no extension above is usually a deployment
        // pointing at the wrong certificate. Folding the two into one reason would leave
        // whoever reads the log unable to tell a misconfiguration from an attack.
        X509Certificate malformed = BuildCertificate(new byte[] { 0x30, 0x82, 0xFF, 0xFF, 0x01 });

        Assert.False(KeyDescription.TryReadFrom(
            malformed,
            out KeyDescription? nothing,
            out AttestationFailureReason malformedReason));

        Assert.Null(nothing);
        Assert.Equal(AttestationFailureReason.MalformedAttestationExtension, malformedReason);

        // The control: the same path over a well-formed extension reports no failure, so
        // the reason above is a decision and not a constant.
        X509Certificate wellFormed = BuildCertificate(KeyDescriptionBuilder.RealisticLayout().Build());

        Assert.True(KeyDescription.TryReadFrom(
            wellFormed,
            out KeyDescription? description,
            out AttestationFailureReason reason));

        Assert.NotNull(description);
        Assert.Equal(AttestationFailureReason.None, reason);
    }

    // ---------------------------------------------------------------------------------
    // Real device bytes. Skipped, by name and by path, on a machine without the vector.
    // ---------------------------------------------------------------------------------

    [FixtureFact(TestVectors.AndroidLeafPath)]
    public void AC5_RealDeviceLeaf_KeyDescription_IsFullyParsed()
    {
        KeyDescription description = ParseRealDeviceLeaf();

        Assert.True(description.AttestationVersion > 0);
        Assert.True(Enum.IsDefined(description.AttestationSecurityLevel));
        Assert.True(description.KeymasterVersion > 0);
        Assert.True(Enum.IsDefined(description.KeymasterSecurityLevel));

        // Length, not content: the challenge itself belongs to the device and is never
        // written into this repository.
        Assert.Equal(32, description.AttestationChallenge.Length);

        // Populated only for an application holding a privileged permission, which this
        // one does not.
        Assert.True(description.UniqueId.IsEmpty);

        Assert.NotNull(description.HardwareEnforced.Origin);
        Assert.NotNull(description.HardwareEnforced.RootOfTrust);
        Assert.Equal(32, description.HardwareEnforced.RootOfTrust!.VerifiedBootKey.Length);
        Assert.True(description.HardwareEnforced.RootOfTrust.HasVerifiedBootHash);
        Assert.Equal(32, description.HardwareEnforced.RootOfTrust.VerifiedBootHash.Length);

        // Nothing in the record was ignored. Any tag the parser did not understand is
        // listed here rather than dropped, so this reads as coverage rather than as luck.
        Assert.Empty(description.HardwareEnforced.UnknownTags);
        Assert.Empty(description.SoftwareEnforced.UnknownTags);
    }

    [FixtureFact(TestVectors.AndroidLeafPath)]
    public void AC6_RealDeviceLeaf_AttestationApplicationId_IsInSoftwareEnforcedNotHardware()
    {
        KeyDescription description = ParseRealDeviceLeaf();

        // The commissioning document lists tag 709 under "Policy (hardwareEnforced)".
        // Measured on this device, it is in the software-enforced list. A verifier written
        // from the document would look for it in the hardware-enforced list, find nothing,
        // and reject every genuine Android device. This assertion is the reason that
        // mistake cannot come back.
        Assert.NotNull(description.SoftwareEnforced.AttestationApplicationId);
        Assert.Null(description.HardwareEnforced.AttestationApplicationId);

        AttestationApplicationId applicationId =
            description.SoftwareEnforced.AttestationApplicationId!;

        Assert.NotEmpty(applicationId.PackageInfos);
        Assert.NotEmpty(applicationId.SignatureDigests);

        // Shape only. The package name and the signing digest identify a real application
        // and are read from the vector, never written into a test.
        Assert.All(
            applicationId.PackageInfos,
            package =>
            {
                Assert.False(string.IsNullOrWhiteSpace(package.PackageName));
                Assert.True(package.Version > 0);
            });

        Assert.All(
            applicationId.SignatureDigests,
            digest => Assert.NotEqual(0, digest.Length));
    }

    [FixtureFact(TestVectors.AndroidLeafPath)]
    public void AC5_RealDeviceLeaf_RootOfTrust_ReportsLockedAndVerified()
    {
        KeyDescription description = ParseRealDeviceLeaf();
        RootOfTrust rootOfTrust = description.HardwareEnforced.RootOfTrust!;

        Assert.NotNull(rootOfTrust);
        Assert.True(rootOfTrust.DeviceLocked);
        Assert.Equal(VerifiedBootState.Verified, rootOfTrust.VerifiedBootState);

        // Read from the hardware-enforced list, which is the only place these values mean
        // anything. The software-enforced list on this device carries no root of trust at
        // all, so a verifier reading from there would have nothing to check.
        Assert.Equal(AuthorizationListSource.HardwareEnforced, description.HardwareEnforced.Source);
        Assert.Null(description.SoftwareEnforced.RootOfTrust);
    }

    // ---------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------

    /// <summary>
    /// Asserts that an input is rejected and that the rejection arrives as a return value
    /// rather than as an exception.
    /// </summary>
    private static void AssertRejectedWithoutThrowing(byte[] input)
    {
        bool parsed = true;
        KeyDescription? description = null;

        Exception? failure = Record.Exception(
            () => parsed = KeyDescription.TryParse(input, out description));

        Assert.Null(failure);
        Assert.False(parsed);
        Assert.Null(description);
    }

    /// <summary>Reads and parses the extension out of the real device leaf certificate.</summary>
    private static KeyDescription ParseRealDeviceLeaf()
    {
        string pem = File.ReadAllText(TestVectors.Resolve(TestVectors.AndroidLeafPath));
        X509Certificate leaf = PemRootStore.LoadFromPem(pem)[0];

        Assert.True(KeyDescription.TryReadFrom(
            leaf,
            out KeyDescription? description,
            out AttestationFailureReason reason));

        Assert.Equal(AttestationFailureReason.None, reason);
        Assert.NotNull(description);
        return description!;
    }

    /// <summary>
    /// Builds a throwaway self-signed certificate, optionally carrying the key attestation
    /// extension with the octets given.
    /// </summary>
    /// <remarks>
    /// Generated rather than committed. A certificate checked into the repository to serve
    /// this test would be a device certificate by another name, and the two failure reasons
    /// under test are about the extension's presence and shape, neither of which needs a
    /// real device to produce.
    /// </remarks>
    private static X509Certificate BuildCertificate(byte[]? extensionOctets)
    {
        SecureRandom random = new SecureRandom();
        ECKeyPairGenerator keyGenerator = new ECKeyPairGenerator();
        keyGenerator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));
        AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

        X509Name name = new X509Name("CN=MobileAttest Test");
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.One);
        generator.SetIssuerDN(name);
        generator.SetSubjectDN(name);
        generator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        generator.SetPublicKey(keyPair.Public);

        if (extensionOctets is not null)
        {
            // The extension is added as an X509Extension rather than through the byte[]
            // overload. Measured: that overload wraps the bytes in an OCTET STRING of their
            // own before the extension wraps them again, so what comes back out is not what
            // went in -- and a test built on it would be testing the wrapper, not the
            // parser. This route round-trips the octets exactly, including octets that are
            // not valid ASN.1 at all, which is what the malformed case needs.
            generator.AddExtension(
                new DerObjectIdentifier(AndroidOids.KeyAttestationExtension),
                new X509Extension(critical: false, new DerOctetString(extensionOctets)));
        }

        return generator.Generate(
            new Asn1SignatureFactory("SHA256WITHECDSA", keyPair.Private, random));
    }
}
