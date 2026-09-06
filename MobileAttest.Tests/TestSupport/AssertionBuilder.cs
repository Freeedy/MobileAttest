using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// Builds App Attest assertions from keys generated here, so the accepting path can be
/// exercised on any machine.
/// </summary>
/// <remarks>
/// <para>
/// These are stand-ins, not device captures. The key is generated on every run, the
/// application identity is invented, and nothing here could be committed by accident.
/// </para>
/// <para>
/// <b>What a synthetic assertion is for.</b> It reaches cases no single capture can -- a
/// counter that goes backwards, a signature by a stranger's key, a wrong application identity
/// -- and it runs on a clean clone. That a signature a real Secure Enclave produced is
/// accepted is proved separately, on the device vector, because only a device can supply that.
/// </para>
/// <para>
/// The signer used here is the one the code under test uses, which on its own would only show
/// that BouncyCastle agrees with itself. Two things break that circle: the vector, which
/// nobody in this repository signed, and <see cref="SignOverRawConcatenation"/> -- the other
/// reading of Apple's assertion step, which must be refused. The accepting tests are therefore
/// pinned against a near miss rather than against nothing.
/// </para>
/// </remarks>
public static class AssertionBuilder
{
    /// <summary>
    /// The flags byte a real iOS assertion carries.
    /// </summary>
    /// <remarks>
    /// Measured on the device capture: <c>0x40</c>, the attested-credential-data bit, set over
    /// 37 bytes that carry no credential data at all. Synthetic assertions use the same value
    /// so they exercise the same contradiction genuine traffic does.
    /// </remarks>
    public const byte AssertionFlags = 0x40;

    /// <summary>The length of an assertion's authenticator data, which is fixed.</summary>
    public const int AssertionAuthenticatorDataLength = 37;

    private const int KeySizeBits = 256;
    private const string SignatureAlgorithm = "SHA-256withECDSA";

    /// <summary>Generates a fresh P-256 key pair.</summary>
    public static AsymmetricCipherKeyPair GenerateKeyPair()
    {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), KeySizeBits));
        return generator.GenerateKeyPair();
    }

    /// <summary>Encodes a public key as the DER SubjectPublicKeyInfo a caller would store.</summary>
    /// <param name="publicKey">The key to encode.</param>
    public static byte[] PublicKeyDer(AsymmetricKeyParameter publicKey) =>
        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey).GetDerEncoded();

    /// <summary>Reads the SubjectPublicKeyInfo out of a certificate, as DER.</summary>
    /// <param name="certificate">The certificate holding the attested key.</param>
    public static byte[] PublicKeyDer(X509Certificate certificate) =>
        certificate.SubjectPublicKeyInfo.GetDerEncoded();

    /// <summary>Derives the relying-party identifier hash from an application identity.</summary>
    /// <param name="appId">The identity, in the form <c>"{teamId}.{bundleId}"</c>.</param>
    /// <remarks>
    /// Written out here rather than taken from the library, so a test comparing against it is
    /// an oracle and not a mirror of the code under test.
    /// </remarks>
    public static byte[] RpIdHash(string appId) => Sha256(Encoding.UTF8.GetBytes(appId));

    /// <summary>Assembles authenticator data in the assertion layout.</summary>
    /// <param name="rpIdHash">The 32-byte relying-party identifier hash.</param>
    /// <param name="signCount">The counter to write, big endian.</param>
    /// <param name="flags">The flags byte. Defaults to what a device sends.</param>
    public static byte[] AuthenticatorData(byte[] rpIdHash, uint signCount, byte flags = AssertionFlags)
    {
        ArgumentNullException.ThrowIfNull(rpIdHash);

        byte[] data = new byte[AssertionAuthenticatorDataLength];
        rpIdHash.CopyTo(data, 0);
        data[32] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(33, 4), signCount);
        return data;
    }

    /// <summary>
    /// Computes an assertion's nonce.
    /// </summary>
    /// <param name="authenticatorData">The authenticator data the device sent.</param>
    /// <param name="clientDataHash">The digest binding the assertion to a request.</param>
    /// <returns><c>SHA-256(authenticatorData ‖ clientDataHash)</c>.</returns>
    /// <remarks>
    /// Written out here rather than taken from the library, so a test comparing against it is
    /// an oracle and not a mirror of the code under test.
    /// </remarks>
    public static byte[] Nonce(byte[] authenticatorData, byte[] clientDataHash) =>
        Sha256(authenticatorData, clientDataHash);

    /// <summary>
    /// Signs an assertion the way a device does: the nonce, handed over as a message.
    /// </summary>
    /// <param name="privateKey">The key to sign with.</param>
    /// <param name="authenticatorData">The authenticator data the assertion carries.</param>
    /// <param name="clientDataHash">The digest binding the assertion to a request.</param>
    /// <returns>The DER encoded ECDSA signature.</returns>
    /// <remarks>
    /// The signer digests what it is handed, so the value under this signature is
    /// <c>SHA-256(nonce)</c>. That is the construction measured on a real capture and the one
    /// the verifier checks -- see <see cref="MobileAttest.Apple.AppleAssertionDigest"/>.
    /// </remarks>
    public static byte[] SignAssertion(
        AsymmetricKeyParameter privateKey,
        byte[] authenticatorData,
        byte[] clientDataHash) =>
        Sign(privateKey, Nonce(authenticatorData, clientDataHash));

    /// <summary>
    /// Signs the raw concatenation instead, which is the reading the library refuses.
    /// </summary>
    /// <param name="privateKey">The key to sign with.</param>
    /// <param name="authenticatorData">The authenticator data the assertion carries.</param>
    /// <param name="clientDataHash">The digest binding the assertion to a request.</param>
    /// <returns>The DER encoded ECDSA signature over the concatenation.</returns>
    /// <remarks>
    /// <para>
    /// The value under this signature is the nonce itself. It is the other way of reading
    /// "verify that the signature is valid for the nonce", and it is a near miss rather than
    /// nonsense: everything about it is right except which of the two values the signer was
    /// handed.
    /// </para>
    /// <para>
    /// It exists so the accepting tests are pinned against something a hair away from correct.
    /// A verifier that accepted both would call twice as many signatures valid as a device can
    /// produce.
    /// </para>
    /// </remarks>
    public static byte[] SignOverRawConcatenation(
        AsymmetricKeyParameter privateKey,
        byte[] authenticatorData,
        byte[] clientDataHash) =>
        Sign(privateKey, authenticatorData, clientDataHash);

    /// <summary>
    /// Signs the concatenation of the parts with <c>SHA-256withECDSA</c>.
    /// </summary>
    /// <param name="privateKey">The key to sign with.</param>
    /// <param name="messageParts">The message, in order.</param>
    /// <returns>The DER encoded ECDSA signature.</returns>
    /// <remarks>
    /// The low-level primitive both constructions above are built from. Tests name the
    /// construction they mean rather than calling this and leaving the reader to work out
    /// which of the two they got.
    /// </remarks>
    public static byte[] Sign(AsymmetricKeyParameter privateKey, params byte[][] messageParts)
    {
        ISigner signer = SignerUtilities.GetSigner(SignatureAlgorithm);
        signer.Init(forSigning: true, privateKey);

        foreach (byte[] part in messageParts)
        {
            signer.BlockUpdate(part, 0, part.Length);
        }

        return signer.GenerateSignature();
    }

    /// <summary>Computes the SHA-256 of the parts, digested in order.</summary>
    /// <param name="parts">The buffers to digest.</param>
    public static byte[] Sha256(params byte[][] parts)
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
}

/// <summary>
/// One synthetic assertion: a generated key, the authenticator data it signed over, and the
/// CBOR object a device would have sent.
/// </summary>
public sealed class SyntheticAssertion
{
    /// <summary>The application identity a synthetic assertion is built under.</summary>
    /// <remarks>Invented. Nothing read from a device vector is written into this file.</remarks>
    public const string DefaultAppId = "SYNTHTEAM1.com.example.synthetic";

    private SyntheticAssertion(
        AsymmetricCipherKeyPair keyPair,
        string appId,
        byte[] rpIdHash,
        uint signCount,
        byte[] authenticatorData,
        byte[] clientDataHash,
        byte[] signature)
    {
        KeyPair = keyPair;
        AppId = appId;
        RpIdHash = rpIdHash;
        SignCount = signCount;
        AuthenticatorData = authenticatorData;
        ClientDataHash = clientDataHash;
        Signature = signature;
    }

    /// <summary>The key pair that signed this assertion.</summary>
    public AsymmetricCipherKeyPair KeyPair { get; }

    /// <summary>The application identity this assertion claims.</summary>
    public string AppId { get; }

    /// <summary>The relying-party identifier hash inside the authenticator data.</summary>
    public byte[] RpIdHash { get; }

    /// <summary>The counter written into the authenticator data.</summary>
    public uint SignCount { get; }

    /// <summary>The authenticator data, exactly as the object carries it.</summary>
    public byte[] AuthenticatorData { get; }

    /// <summary>The client data hash the signature is bound to.</summary>
    public byte[] ClientDataHash { get; }

    /// <summary>The DER encoded signature.</summary>
    public byte[] Signature { get; }

    /// <summary>The attested public key as a caller would have stored it.</summary>
    public byte[] PublicKeyDer => AssertionBuilder.PublicKeyDer(KeyPair.Public);

    /// <summary>The CBOR assertion object a device would have sent.</summary>
    public byte[] Object => CborBuilder.AssertionObject(Signature, AuthenticatorData);

    /// <summary>
    /// Builds one assertion, signing it the way App Attest is defined over unless told
    /// otherwise.
    /// </summary>
    /// <param name="signCount">The counter to write. Defaults to a first assertion's value.</param>
    /// <param name="appId">The application identity to hash into the authenticator data.</param>
    /// <param name="clientDataHash">
    /// The digest binding the assertion to a request. Defaults to an invented 32-byte value.
    /// </param>
    /// <param name="keyPair">The key to sign with. Defaults to a freshly generated one.</param>
    /// <param name="flags">The flags byte to write.</param>
    /// <param name="sign">
    /// How to produce the signature from the private key, the authenticator data and the
    /// client data hash. Defaults to the construction a device uses.
    /// </param>
    public static SyntheticAssertion Create(
        uint signCount = 1,
        string appId = DefaultAppId,
        byte[]? clientDataHash = null,
        AsymmetricCipherKeyPair? keyPair = null,
        byte flags = AssertionBuilder.AssertionFlags,
        Func<AsymmetricKeyParameter, byte[], byte[], byte[]>? sign = null)
    {
        AsymmetricCipherKeyPair pair = keyPair ?? AssertionBuilder.GenerateKeyPair();
        byte[] rpIdHash = AssertionBuilder.RpIdHash(appId);
        byte[] authenticatorData = AssertionBuilder.AuthenticatorData(rpIdHash, signCount, flags);
        byte[] hash = clientDataHash ?? InventedClientDataHash(signCount);

        byte[] signature = sign is null
            ? AssertionBuilder.SignAssertion(pair.Private, authenticatorData, hash)
            : sign(pair.Private, authenticatorData, hash);

        return new SyntheticAssertion(pair, appId, rpIdHash, signCount, authenticatorData, hash, signature);
    }

    /// <summary>Rebuilds the object around a different signature or different authenticator data.</summary>
    /// <param name="signature">The signature to carry, or null to keep this one.</param>
    /// <param name="authenticatorData">The authenticator data to carry, or null to keep this one.</param>
    public byte[] ObjectWith(byte[]? signature = null, byte[]? authenticatorData = null) =>
        CborBuilder.AssertionObject(
            signature ?? Signature,
            authenticatorData ?? AuthenticatorData);

    /// <summary>
    /// A 32-byte value standing in for <c>SHA-256(requestBody ‖ nonce)</c>.
    /// </summary>
    /// <remarks>
    /// Building the digest is the caller's job and is outside this library, so what matters
    /// here is only that two assertions in one test can differ. It is derived from the counter
    /// so that they do.
    /// </remarks>
    private static byte[] InventedClientDataHash(uint signCount) =>
        AssertionBuilder.Sha256(new[] { BitConverter.GetBytes(signCount) });
}
