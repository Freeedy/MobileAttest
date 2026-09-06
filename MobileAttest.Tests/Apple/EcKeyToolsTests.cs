using MobileAttest.Apple;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.Apple;

/// <summary>
/// Guards the derivation the whole Apple side rests on: a public key to its uncompressed
/// point, and that point to the key identifier.
/// </summary>
/// <remarks>
/// <para>
/// The expected point is rebuilt here from the coordinates as integers, padded by a routine
/// written in this file. That matters: reading it back with the same encoder the code under
/// test uses would only prove that BouncyCastle agrees with itself, and the exact defect
/// these tests exist for -- a coordinate emitted one byte short -- is invisible to that
/// comparison.
/// </para>
/// <para>
/// The keys are generated or derived here, so these tests need no vector and run on any
/// machine. That a real device's identifier comes out of this derivation is proved by the
/// vector test in <see cref="AppleAppAttestVerifierTests"/>, which is the only oracle for it
/// that nobody in this repository wrote.
/// </para>
/// </remarks>
public class EcKeyToolsTests
{
    private const int P256CoordinateLength = 32;

    [Fact]
    public void AC9_EcKeyTools_SpkiToUncompressedPoint_IsCorrect()
    {
        AsymmetricCipherKeyPair keyPair = GenerateKeyPair();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters)keyPair.Public;
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

        Assert.True(EcKeyTools.TryGetUncompressedPoint(spki, out byte[]? point));

        // Rebuilt from the coordinates as numbers, not read back through an encoder.
        ECPoint q = publicKey.Q.Normalize();
        byte[] expected = UncompressedPoint(
            q.AffineXCoord.ToBigInteger(),
            q.AffineYCoord.ToBigInteger());

        Assert.Equal(1 + (2 * P256CoordinateLength), point!.Length);
        Assert.Equal(0x04, point[0]);
        Assert.Equal(expected, point);

        // The identifier is the digest of exactly those bytes and nothing else -- no length
        // prefix, no algorithm identifier, no re-encoding of the certificate around it.
        Assert.True(EcKeyTools.TryComputeKeyId(spki, out byte[]? keyId));
        Assert.Equal(Sha256(expected), keyId);

        // A key of the wrong kind is answered, not thrown at. It reaches this code from a
        // device-supplied certificate.
        RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
        rsaGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
        SubjectPublicKeyInfo rsa =
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rsaGenerator.GenerateKeyPair().Public);

        Assert.False(EcKeyTools.TryGetUncompressedPoint(rsa, out byte[]? noPoint));
        Assert.Null(noPoint);
        Assert.False(EcKeyTools.TryComputeKeyId(rsa, out byte[]? noKeyId));
        Assert.Null(noKeyId);

        Assert.False(EcKeyTools.TryGetUncompressedPoint(null!, out byte[]? nullPoint));
        Assert.Null(nullPoint);
    }

    [Fact]
    public void AC9_EcKeyTools_LeadingZeroCoordinate_IsPaddedToFullLength()
    {
        // A key whose X or Y is numerically small enough to encode in fewer than 32 bytes.
        // About one key in a hundred and twenty-eight is, so a randomly generated key would
        // make this test pass almost always and fail for nobody in particular. Walking small
        // multiples of the generator finds one at the same multiplier on every machine and
        // every run.
        (ECPublicKeyParameters PublicKey, BigInteger X, BigInteger Y, int Multiplier) shortKey =
            FindKeyWithShortCoordinate();

        SubjectPublicKeyInfo spki =
            SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(shortKey.PublicKey);

        Assert.True(EcKeyTools.TryGetUncompressedPoint(spki, out byte[]? point));

        // The property under test: a coordinate short by a byte is padded on the left, so the
        // point is always 65 bytes and X always begins at offset 1.
        Assert.Equal(1 + (2 * P256CoordinateLength), point!.Length);
        Assert.Equal(
            UncompressedPoint(shortKey.X, shortKey.Y),
            point);
        Assert.True(
            shortKey.X.ToByteArrayUnsigned().Length < P256CoordinateLength ||
            shortKey.Y.ToByteArrayUnsigned().Length < P256CoordinateLength,
            $"the multiplier {shortKey.Multiplier} was expected to yield a short coordinate");

        // And why it matters. The minimal encoding is a different byte sequence, so it
        // digests to a different identifier -- one that would match no device, silently.
        byte[] minimal = Concat(
            new byte[] { 0x04 },
            shortKey.X.ToByteArrayUnsigned(),
            shortKey.Y.ToByteArrayUnsigned());

        Assert.True(EcKeyTools.TryComputeKeyId(spki, out byte[]? keyId));
        Assert.Equal(Sha256(point), keyId);
        Assert.NotEqual(Sha256(minimal), keyId);
    }

    /// <summary>
    /// Walks small multiples of the P-256 generator until one has a coordinate whose
    /// big-endian magnitude is shorter than the field.
    /// </summary>
    private static (ECPublicKeyParameters PublicKey, BigInteger X, BigInteger Y, int Multiplier)
        FindKeyWithShortCoordinate()
    {
        X9ECParameters curve = ECNamedCurveTable.GetByName("P-256");
        ECNamedDomainParameters domain = new ECNamedDomainParameters(
            SecObjectIdentifiers.SecP256r1,
            curve);

        for (int multiplier = 1; multiplier <= 4096; multiplier++)
        {
            ECPoint q = curve.G.Multiply(BigInteger.ValueOf(multiplier)).Normalize();
            BigInteger x = q.AffineXCoord.ToBigInteger();
            BigInteger y = q.AffineYCoord.ToBigInteger();

            if (x.ToByteArrayUnsigned().Length < P256CoordinateLength ||
                y.ToByteArrayUnsigned().Length < P256CoordinateLength)
            {
                return (new ECPublicKeyParameters(q, domain), x, y, multiplier);
            }
        }

        // Not a silent skip. If no multiplier in that range has a short coordinate, the test
        // has stopped testing what it says it does and must say so.
        Assert.Fail("no multiple of the generator in the searched range had a short coordinate");
        return default;
    }

    private static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 256));
        return generator.GenerateKeyPair();
    }

    /// <summary>Builds <c>0x04 ‖ X ‖ Y</c> with each coordinate padded on the left.</summary>
    private static byte[] UncompressedPoint(BigInteger x, BigInteger y) =>
        Concat(
            new byte[] { 0x04 },
            PadLeft(x.ToByteArrayUnsigned(), P256CoordinateLength),
            PadLeft(y.ToByteArrayUnsigned(), P256CoordinateLength));

    private static byte[] PadLeft(byte[] value, int length)
    {
        Assert.True(value.Length <= length, "the coordinate does not fit the field");

        byte[] padded = new byte[length];
        value.CopyTo(padded, length - value.Length);
        return padded;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        byte[] joined = new byte[parts.Sum(part => part.Length)];
        int offset = 0;

        foreach (byte[] part in parts)
        {
            part.CopyTo(joined, offset);
            offset += part.Length;
        }

        return joined;
    }

    private static byte[] Sha256(byte[] value)
    {
        Sha256Digest digest = new Sha256Digest();
        digest.BlockUpdate(value, 0, value.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }
}
