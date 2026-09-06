using System.Text;
using MobileAttest.Trust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.Trust;

/// <summary>
/// Round-trips the pinned root loader. The certificate is generated here rather than
/// checked in: no real device or organisation vector exists in this repository, and a
/// generated one keeps the test self-contained.
/// </summary>
public class PemRootStoreTests
{
    private static string CreateSelfSignedCertificatePem()
    {
        SecureRandom random = new SecureRandom();

        ECKeyPairGenerator keyGenerator = new ECKeyPairGenerator();
        keyGenerator.Init(new KeyGenerationParameters(random, 256));
        AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

        X509Name subject = new X509Name("CN=MobileAttest Test Root");
        X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
        certificateGenerator.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
        certificateGenerator.SetIssuerDN(subject);
        certificateGenerator.SetSubjectDN(subject);
        certificateGenerator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        certificateGenerator.SetNotAfter(DateTime.UtcNow.AddDays(1));
        certificateGenerator.SetPublicKey(keyPair.Public);

        ISignatureFactory signatureFactory =
            new Asn1SignatureFactory("SHA256withECDSA", keyPair.Private, random);
        X509Certificate certificate = certificateGenerator.Generate(signatureFactory);

        StringWriter text = new StringWriter();
        PemWriter pemWriter = new PemWriter(text);
        pemWriter.WriteObject(certificate);
        pemWriter.Writer.Flush();
        return text.ToString();
    }

    [Fact]
    public void AC7_PemRootStore_LoadsValidPem_AndRejectsMalformedPem()
    {
        string pem = CreateSelfSignedCertificatePem();

        IReadOnlyList<X509Certificate> roots = PemRootStore.LoadFromPem(pem);

        Assert.Single(roots);
        Assert.Equal("CN=MobileAttest Test Root", roots[0].SubjectDN.ToString());

        // Two concatenated certificates must both be loaded, not just the first.
        IReadOnlyList<X509Certificate> pair =
            PemRootStore.LoadFromPem(pem + CreateSelfSignedCertificatePem());
        Assert.Equal(2, pair.Count);

        // Text with no PEM block at all. The failure mode this guards against is a loader
        // returning an empty list, which reads as "no roots configured" and disables
        // pinning without any error surfacing.
        Assert.Throws<FormatException>(() => PemRootStore.LoadFromPem("not a certificate"));
        Assert.Throws<FormatException>(() => PemRootStore.LoadFromPem(string.Empty));

        // A well-formed envelope wrapped around a corrupt body must also be rejected.
        string corrupt = new StringBuilder()
            .AppendLine("-----BEGIN CERTIFICATE-----")
            .AppendLine("TW9iaWxlQXR0ZXN0IGlzIG5vdCBhIGNlcnRpZmljYXRl")
            .AppendLine("-----END CERTIFICATE-----")
            .ToString();
        Assert.Throws<FormatException>(() => PemRootStore.LoadFromPem(corrupt));

        Assert.Throws<ArgumentNullException>(() => PemRootStore.LoadFromPem(null!));
    }
}
