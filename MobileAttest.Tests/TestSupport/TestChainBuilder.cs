using MobileAttest.Android;
using MobileAttest.Apple;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// Builds a root, an intermediate and a leaf so that chain validation can be exercised in
/// both directions on any machine.
/// </summary>
/// <remarks>
/// <para>
/// These are stand-ins, not device vectors. They carry no real key, no real application
/// identity and nothing that could be committed by accident, and they are generated fresh
/// on every run, so no expiry date is ever baked into the repository.
/// </para>
/// <para>
/// What they prove is the engine, in both directions: a chain reaching the anchor it was
/// built under is accepted, and the same chain offered against a different anchor is
/// refused. What they cannot prove is that a real device chain reaches a real platform
/// root -- no platform root is present here, so that claim is not made anywhere in this
/// project.
/// </para>
/// </remarks>
public static class TestChainBuilder
{
    private const int KeySizeBits = 256;
    private const string SignatureAlgorithm = "SHA256withECDSA";

    /// <summary>The start of the validity window a chain gets unless one is asked for.</summary>
    public static readonly DateTime DefaultNotBefore = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>The end of the validity window a chain gets unless one is asked for.</summary>
    public static readonly DateTime DefaultNotAfter = new(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>
    /// Builds a three-certificate hierarchy whose certificates all share one validity
    /// window.
    /// </summary>
    /// <param name="name">
    /// A name to distinguish this hierarchy from another built in the same test. It lands
    /// in the subject names, which is what makes two hierarchies genuinely unrelated
    /// rather than merely differently keyed.
    /// </param>
    /// <param name="notBefore">The start of the validity window. Defaults to <see cref="DefaultNotBefore"/>.</param>
    /// <param name="notAfter">The end of the validity window. Defaults to <see cref="DefaultNotAfter"/>.</param>
    /// <param name="leafKeyAttestationExtension">
    /// Octets to place in the leaf's key attestation extension, or null to issue a leaf that
    /// carries no such extension. <b>They do not arrive at the parser unchanged</b> -- see the
    /// remarks -- so this is for extensions a test expects to be rejected. To issue a leaf
    /// whose extension actually parses, use <paramref name="leafKeyAttestationRecord"/>.
    /// </param>
    /// <param name="leafKeyAttestationRecord">
    /// A DER-encoded KeyDescription to place in the leaf's key attestation extension so that it
    /// reads back byte for byte, or null to add no such extension.
    /// </param>
    /// <param name="leafAppleNonceExtension">
    /// Builds the octets for the leaf's Apple attestation nonce extension from the leaf's own
    /// public key, or null to issue a leaf that carries no such extension.
    /// </param>
    /// <returns>The built hierarchy.</returns>
    /// <remarks>
    /// <para>
    /// <b>Measured</b>, on BouncyCastle 2.7.0: the generator's <c>byte[]</c> extension overload
    /// treats its argument as the content of the extension's OCTET STRING and wraps it again,
    /// so what a parser later reads out of the certificate is <c>04 &lt;len&gt; input</c> and
    /// not <c>input</c>. A valid KeyDescription passed that way comes back as a malformed one.
    /// That is why <paramref name="leafKeyAttestationRecord"/> exists as a separate parameter
    /// rather than as a nicer name for the same thing: it takes the
    /// <c>Asn1Encodable</c> route, which puts the exact octets in the certificate, and it
    /// refuses input the encoder would not reproduce verbatim.
    /// </para>
    /// <para>
    /// The two are not interchangeable and both are needed. A test that wants an extension the
    /// parser must reject has to be able to write bytes no encoder would produce, and a test
    /// that wants a leaf which verifies has to be able to write bytes that survive the trip.
    /// </para>
    /// <para>
    /// The Apple extension arrives as a function of the key rather than as bytes because the
    /// two are circular in the real object: the nonce covers the authenticator data, the
    /// authenticator data carries the credential identifier, and the credential identifier is
    /// a digest of this very key. A caller that were handed the certificate first and asked
    /// to add the extension afterwards would be describing a different key than the one the
    /// certificate attests, which is exactly the mismatch these tests exist to detect.
    /// </para>
    /// </remarks>
    public static TestChain Create(
        string name = "MobileAttest Test",
        DateTime? notBefore = null,
        DateTime? notAfter = null,
        byte[]? leafKeyAttestationExtension = null,
        Func<AsymmetricKeyParameter, byte[]>? leafAppleNonceExtension = null,
        byte[]? leafKeyAttestationRecord = null)
    {
        ArgumentNullException.ThrowIfNull(name);

        DateTime from = notBefore ?? DefaultNotBefore;
        DateTime to = notAfter ?? DefaultNotAfter;

        SecureRandom random = new SecureRandom();

        (X509Certificate Certificate, AsymmetricCipherKeyPair KeyPair) root =
            Issue(random, $"{name} Root", isCertificateAuthority: true, from, to, issuer: null, issuerKey: null);

        (X509Certificate Certificate, AsymmetricCipherKeyPair KeyPair) intermediate =
            Issue(random, $"{name} Intermediate", isCertificateAuthority: true, from, to, root.Certificate, root.KeyPair.Private);

        (X509Certificate Certificate, AsymmetricCipherKeyPair KeyPair) leaf =
            Issue(
                random,
                $"{name} Leaf",
                isCertificateAuthority: false,
                from,
                to,
                intermediate.Certificate,
                intermediate.KeyPair.Private,
                leafKeyAttestationExtension,
                leafAppleNonceExtension,
                leafKeyAttestationRecord);

        return new TestChain(root.Certificate, intermediate.Certificate, leaf.Certificate, from, to);
    }

    private static (X509Certificate Certificate, AsymmetricCipherKeyPair KeyPair) Issue(
        SecureRandom random,
        string commonName,
        bool isCertificateAuthority,
        DateTime notBefore,
        DateTime notAfter,
        X509Certificate? issuer,
        AsymmetricKeyParameter? issuerKey,
        byte[]? keyAttestationExtension = null,
        Func<AsymmetricKeyParameter, byte[]>? appleNonceExtension = null,
        byte[]? keyAttestationRecord = null)
    {
        ECKeyPairGenerator keyGenerator = new ECKeyPairGenerator();
        keyGenerator.Init(new KeyGenerationParameters(random, KeySizeBits));
        AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

        X509Name subject = new X509Name($"CN={commonName}");
        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(new BigInteger(64, random).Abs().Add(BigInteger.One));
        generator.SetIssuerDN(issuer?.SubjectDN ?? subject);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(keyPair.Public);

        // Path validation refuses a signing certificate that does not say it is one, so
        // these are what make the hierarchy validate at all rather than decoration.
        generator.AddExtension(
            X509Extensions.BasicConstraints,
            critical: true,
            new BasicConstraints(isCertificateAuthority));
        generator.AddExtension(
            X509Extensions.KeyUsage,
            critical: true,
            new KeyUsage(isCertificateAuthority
                ? KeyUsage.KeyCertSign | KeyUsage.CrlSign
                : KeyUsage.DigitalSignature));

        if (keyAttestationExtension is not null)
        {
            // The octets are written verbatim, so a test can put something in this extension
            // that no encoder would produce. That is the point: the difference between "no
            // extension" and "an extension that will not parse" is two different failure
            // reasons, and there is no other way to reach the second one.
            generator.AddExtension(
                AndroidOids.KeyAttestationExtension,
                critical: false,
                keyAttestationExtension);
        }

        if (keyAttestationRecord is not null)
        {
            // The exact-octets route, for the same reason the Apple extension below uses it:
            // the byte[] overload adds a layer, and a leaf built with it can never carry a
            // record the parser accepts. The round-trip guard refuses input the encoder would
            // rewrite, so a record that reaches the certificate is the record that was written.
            Asn1Object record = Asn1Object.FromByteArray(keyAttestationRecord);

            if (!record.GetDerEncoded().SequenceEqual(keyAttestationRecord))
            {
                throw new ArgumentException(
                    "The certificate encoder would not reproduce this record verbatim. A record " +
                    "meant to be rejected belongs in keyAttestationExtension instead.",
                    nameof(keyAttestationRecord));
            }

            generator.AddExtension(
                new DerObjectIdentifier(AndroidOids.KeyAttestationExtension),
                critical: false,
                record);
        }

        if (appleNonceExtension is not null)
        {
            // Measured, and the reason this does not use the byte[] overload as the Android
            // extension above does: that overload treats its argument as the *content* of the
            // extension's OCTET STRING and wraps it again, so a certificate built with it
            // carries one more layer than a real one. The Android tests never noticed, because
            // every extension they build that way is one they expect to be rejected.
            //
            // Going through Asn1Encodable puts the exact octets in the certificate, and the
            // round-trip below refuses anything the encoder would not reproduce byte for byte
            // -- a test whose input was silently rewritten on the way in proves nothing.
            byte[] octets = appleNonceExtension(keyPair.Public);
            Asn1Object parsed = Asn1Object.FromByteArray(octets);

            if (!parsed.GetDerEncoded().SequenceEqual(octets))
            {
                throw new ArgumentException(
                    "The certificate encoder would not reproduce these octets verbatim. Shapes " +
                    "it cannot carry are exercised against the parser directly instead.",
                    nameof(appleNonceExtension));
            }

            generator.AddExtension(
                new DerObjectIdentifier(AppleOids.AttestationNonceExtension),
                critical: false,
                parsed);
        }

        // A root signs itself; everything else is signed by the certificate above it.
        ISignatureFactory signatureFactory =
            new Asn1SignatureFactory(SignatureAlgorithm, issuerKey ?? keyPair.Private, random);

        return (generator.Generate(signatureFactory), keyPair);
    }
}

/// <summary>One generated hierarchy: a root, the intermediate it signed, and the leaf.</summary>
public sealed class TestChain
{
    internal TestChain(
        X509Certificate root,
        X509Certificate intermediate,
        X509Certificate leaf,
        DateTime notBefore,
        DateTime notAfter)
    {
        Root = root;
        Intermediate = intermediate;
        Leaf = leaf;
        NotBefore = notBefore;
        NotAfter = notAfter;
    }

    /// <summary>The self-signed root.</summary>
    public X509Certificate Root { get; }

    /// <summary>The intermediate the root signed.</summary>
    public X509Certificate Intermediate { get; }

    /// <summary>The end-entity certificate the intermediate signed.</summary>
    public X509Certificate Leaf { get; }

    /// <summary>The start of the window every certificate here shares.</summary>
    public DateTime NotBefore { get; }

    /// <summary>The end of the window every certificate here shares.</summary>
    public DateTime NotAfter { get; }

    /// <summary>The chain as a device would send it: DER, leaf first, root omitted.</summary>
    public IReadOnlyList<byte[]> Der => new[] { Leaf.GetEncoded(), Intermediate.GetEncoded() };

    /// <summary>This hierarchy's root, as a pinned anchor set.</summary>
    public IReadOnlyList<X509Certificate> PinnedRoots => new[] { Root };

    /// <summary>
    /// The chain with one byte of the intermediate's signature flipped.
    /// </summary>
    /// <remarks>
    /// The last byte of the encoding is inside the signature, so the certificate still
    /// decodes and still names the same subject and issuer. That is the point: the chain
    /// then fails only if the signature is actually verified, which is what distinguishes
    /// a real check from a structural one.
    /// </remarks>
    public IReadOnlyList<byte[]> DerWithTamperedIntermediate
    {
        get
        {
            byte[] tampered = Intermediate.GetEncoded();
            tampered[^1] ^= 0xFF;
            return new[] { Leaf.GetEncoded(), tampered };
        }
    }
}
