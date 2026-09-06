using System;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace MobileAttest.Apple;

/// <summary>
/// Turns an attested elliptic-curve public key into the forms App Attest is defined over:
/// the uncompressed point, the SHA-256 of it that Apple calls the key identifier, and the
/// signature check an assertion is verified with.
/// </summary>
/// <remarks>
/// <para><b>Why this is its own type</b></para>
/// <para>
/// Attestation derives a key identifier from the credential certificate, and assertion has
/// to derive the same identifier from the key a caller stored at enrolment. Two derivations
/// that must agree byte for byte are one derivation: written twice, they would agree until
/// one of them was corrected.
/// </para>
/// <para><b>The encoding is fixed width, not minimal</b></para>
/// <para>
/// The point is <c>0x04 ‖ X ‖ Y</c> with each coordinate padded to the curve's field size.
/// This matters more than it looks: roughly one key in a hundred and twenty-eight has a
/// coordinate whose big-endian magnitude is a byte shorter than the field, and an encoder
/// that emitted the minimal form for those keys would hash 64 bytes instead of 65 and
/// produce an identifier that matches nothing. BouncyCastle's own point encoder is used
/// rather than a padding routine written here, and the result's length and prefix are
/// checked afterwards so a curve with a different encoding cannot pass silently.
/// </para>
/// <para><b>Nothing here is trusted</b></para>
/// <para>
/// The SubjectPublicKeyInfo handed to these methods comes from a device-supplied
/// certificate. A key that is not elliptic curve, a point at infinity, or bytes that do not
/// decode at all are all answered with <see langword="false"/> rather than an exception.
/// </para>
/// </remarks>
internal static class EcKeyTools
{
    /// <summary>The prefix an uncompressed elliptic-curve point carries.</summary>
    private const byte UncompressedPointPrefix = 0x04;

    /// <summary>
    /// The signer name for the algorithm App Attest signs assertions under.
    /// </summary>
    /// <remarks>
    /// This signer hashes the message it is fed with SHA-256 and then signs the digest, which
    /// is why what is handed to <see cref="VerifyEcdsaSha256"/> matters exactly: see the note
    /// there.
    /// </remarks>
    private const string EcdsaWithSha256 = "SHA-256withECDSA";

    /// <summary>
    /// Reads the uncompressed point out of a SubjectPublicKeyInfo.
    /// </summary>
    /// <param name="publicKeyInfo">The key as it appears in a certificate.</param>
    /// <param name="point">
    /// The point as <c>0x04 ‖ X ‖ Y</c>, or <see langword="null"/> when the key was
    /// rejected.
    /// </param>
    /// <returns>Whether a point was produced.</returns>
    internal static bool TryGetUncompressedPoint(
        SubjectPublicKeyInfo publicKeyInfo,
        out byte[]? point)
    {
        point = null;

        if (publicKeyInfo is null)
        {
            return false;
        }

        try
        {
            AsymmetricKeyParameter key = PublicKeyFactory.CreateKey(publicKeyInfo);

            // An RSA or Ed25519 key is a well-formed key and the wrong key. App Attest
            // attests a P-256 key, and there is no meaningful uncompressed point to derive
            // from anything else.
            if (key is not ECPublicKeyParameters ecKey)
            {
                return false;
            }

            // Normalising converts to affine coordinates. Without it the X and Y read back
            // would be projective and the encoding would depend on how the point was
            // arrived at rather than on which point it is.
            Org.BouncyCastle.Math.EC.ECPoint q = ecKey.Q.Normalize();

            if (q.IsInfinity)
            {
                return false;
            }

            byte[] encoded = q.GetEncoded(compressed: false);
            int coordinateLength = (q.Curve.FieldSize + 7) / 8;

            // Asserted rather than assumed: the identifier is a hash of these bytes, so a
            // shorter or differently prefixed encoding would produce an identifier that
            // silently matches nothing instead of failing here.
            if (encoded.Length != 1 + (2 * coordinateLength) ||
                encoded[0] != UncompressedPointPrefix)
            {
                return false;
            }

            point = encoded;
            return true;
        }
        catch (Exception error) when (error is ArgumentException
                                           or InvalidOperationException
                                           or IOException
                                           or FormatException
                                           or SecurityUtilityException)
        {
            // The families BouncyCastle raises on a key structure it cannot decode. This is
            // deliberately not catch-all: a NullReferenceException here would be a defect in
            // this file, and answering false for it would hide the defect behind a rejection
            // that looks exactly like a rejected device.
            point = null;
            return false;
        }
    }

    /// <summary>
    /// Computes the App Attest key identifier for a public key.
    /// </summary>
    /// <param name="publicKeyInfo">The key as it appears in a certificate.</param>
    /// <param name="keyId">
    /// The identifier, or <see langword="null"/> when the key was rejected.
    /// </param>
    /// <returns>Whether an identifier was produced.</returns>
    /// <remarks>
    /// The identifier is recomputed from the certificate rather than taken from anywhere a
    /// device controls. That is the whole point of the step it serves: the device also sends
    /// an identifier, and the two are compared instead of one being believed.
    /// </remarks>
    internal static bool TryComputeKeyId(SubjectPublicKeyInfo publicKeyInfo, out byte[]? keyId)
    {
        if (!TryGetUncompressedPoint(publicKeyInfo, out byte[]? point))
        {
            keyId = null;
            return false;
        }

        keyId = Sha256(point!);
        return true;
    }

    /// <summary>
    /// Reads a stored SubjectPublicKeyInfo back into the elliptic-curve key it encodes.
    /// </summary>
    /// <param name="subjectPublicKeyInfo">The DER SubjectPublicKeyInfo a caller stored.</param>
    /// <param name="publicKey">
    /// The key, or <see langword="null"/> when the bytes were rejected.
    /// </param>
    /// <returns>Whether a key was produced.</returns>
    /// <remarks>
    /// <para>
    /// These bytes are not device input: they are what a caller stored when the key was
    /// attested, so a failure here says the caller's own record is unreadable rather than that
    /// a device misbehaved. They are still parsed defensively, because a record can be
    /// truncated by a schema change or a bad migration as easily as by an attacker, and a
    /// verifier that threw on one would turn a data problem into an outage.
    /// </para>
    /// <para>
    /// A key that is not elliptic curve is refused rather than adapted. App Attest attests a
    /// P-256 key; anything else reaching here was not produced by the path this library
    /// verifies.
    /// </para>
    /// </remarks>
    internal static bool TryReadEcPublicKey(
        ReadOnlySpan<byte> subjectPublicKeyInfo,
        out ECPublicKeyParameters? publicKey)
    {
        publicKey = null;

        if (subjectPublicKeyInfo.IsEmpty)
        {
            return false;
        }

        try
        {
            AsymmetricKeyParameter parsed = PublicKeyFactory.CreateKey(subjectPublicKeyInfo.ToArray());

            if (parsed is not ECPublicKeyParameters ecKey)
            {
                return false;
            }

            publicKey = ecKey;
            return true;
        }
        catch (Exception error) when (error is ArgumentException
                                           or InvalidOperationException
                                           or IOException
                                           or FormatException
                                           or SecurityUtilityException)
        {
            // The same families TryGetUncompressedPoint filters, and for the same reason: a
            // NullReferenceException escaping here would be a defect in this file, and
            // answering false for it would hide that defect behind a rejection.
            publicKey = null;
            return false;
        }
    }

    /// <summary>
    /// Verifies an ECDSA signature over a message, hashed once by the signer.
    /// </summary>
    /// <param name="publicKey">The key the signature must verify under.</param>
    /// <param name="message">The message the signature was made over.</param>
    /// <param name="derSignature">The signature, DER encoded as Apple sends it.</param>
    /// <returns>Whether the signature verified.</returns>
    /// <remarks>
    /// <para><b>What is passed here is the message, and the signer hashes it</b></para>
    /// <para>
    /// <c>SHA-256withECDSA</c> digests what it is given and signs that digest. So the caller
    /// decides which construction is being checked purely by what it hands over, and the two
    /// candidate readings of App Attest's assertion step differ in exactly that: passing the
    /// nonce checks <c>SHA-256(nonce)</c>, passing the raw concatenation checks the nonce
    /// itself. <see cref="AppleAssertionDigest"/> names which one this library uses and why.
    /// </para>
    /// <para>
    /// Getting it wrong is a silent failure, not a loud one: nothing throws, nothing is
    /// logged, and every genuine device is simply refused with a reason that looks exactly
    /// like an attack.
    /// </para>
    /// <para><b>The signature is attacker supplied</b></para>
    /// <para>
    /// It arrives inside the object a device sent, so bytes that are not a DER encoded
    /// ECDSA signature at all are an expected input. They are answered with
    /// <see langword="false"/>, which is the same answer a wrong signature gets: this method
    /// says "this did not verify" and never says why.
    /// </para>
    /// </remarks>
    internal static bool VerifyEcdsaSha256(
        ECPublicKeyParameters publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> derSignature)
    {
        if (publicKey is null || derSignature.IsEmpty)
        {
            return false;
        }

        try
        {
            ISigner verifier = SignerUtilities.GetSigner(EcdsaWithSha256);
            verifier.Init(forSigning: false, publicKey);
            verifier.BlockUpdate(message);

            return verifier.VerifySignature(derSignature.ToArray());
        }
        catch (Exception error) when (error is ArgumentException
                                           or InvalidOperationException
                                           or IOException
                                           or FormatException
                                           or SecurityUtilityException
                                           or CryptoException)
        {
            return false;
        }
    }

    /// <summary>Computes the SHA-256 of one buffer.</summary>
    /// <param name="value">The bytes to digest.</param>
    /// <returns>The 32-byte digest.</returns>
    /// <remarks>
    /// App Attest is defined over SHA-256 throughout -- the key identifier, the
    /// relying-party identifier hash and the nonce are all one -- so there is one
    /// implementation of it in the Apple path rather than one per call site.
    /// </remarks>
    internal static byte[] Sha256(ReadOnlySpan<byte> value)
    {
        Sha256Digest digest = new Sha256Digest();
        digest.BlockUpdate(value);
        return Finish(digest);
    }

    /// <summary>Computes the SHA-256 of two buffers, digested in order.</summary>
    /// <param name="first">The first part.</param>
    /// <param name="second">The second part.</param>
    /// <returns>The 32-byte digest.</returns>
    /// <remarks>
    /// The parts are fed to the digest rather than joined into a new array first. Joining
    /// would copy the authenticator data on every verification for no benefit, and the
    /// concatenation is what the specification defines rather than a buffer it needs.
    /// </remarks>
    internal static byte[] Sha256(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        Sha256Digest digest = new Sha256Digest();
        digest.BlockUpdate(first);
        digest.BlockUpdate(second);
        return Finish(digest);
    }

    private static byte[] Finish(Sha256Digest digest)
    {
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }
}
