using System;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace MobileAttest.Protocol;

/// <summary>
/// Builds the message that anchor proof-of-possession signatures are made over.
/// </summary>
/// <remarks>
/// <para>The message is always</para>
/// <code>
/// SHA256( "mobileattest.anchor.v1" || 0x00 || purpose || 0x00 || payload )
/// </code>
/// <para>
/// The label names the protocol and its version; the purpose names the operation. Both
/// are inside the digest, so a signature made for one protocol or one operation does not
/// verify as another -- the defence against cross-protocol confusion. The zero separators
/// keep the three parts from running together: without them a label and purpose could be
/// re-split at a different point and produce the same bytes.
/// </para>
/// <para>
/// Verification rebuilds this same message and compares. This type performs no signing
/// and no verification itself; it only fixes the construction both sides must agree on.
/// </para>
/// </remarks>
public static class AnchorSignatureContext
{
    /// <summary>The domain separation label, naming the protocol and its version.</summary>
    public const string DomainLabel = "mobileattest.anchor.v1";

    /// <summary>The byte separating the parts of the message.</summary>
    public const byte Separator = 0x00;

    /// <summary>Length in bytes of the digest this type produces.</summary>
    public const int DigestLength = 32;

    /// <summary>Returns the wire label for a purpose.</summary>
    /// <param name="purpose">The purpose to label.</param>
    /// <returns>The exact text that goes into the signed message.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="purpose"/> is not a defined value.</exception>
    public static string GetPurposeLabel(AnchorPurpose purpose) => purpose switch
    {
        AnchorPurpose.AuthToken => "auth-token",
        AnchorPurpose.GateVerify => "gate-verify",
        AnchorPurpose.KeyBinding => "key-binding",
        _ => throw new ArgumentOutOfRangeException(
            nameof(purpose),
            purpose,
            "The purpose is part of the signed message and cannot be an undefined value."),
    };

    /// <summary>
    /// Produces the digest to be signed, or to be verified against.
    /// </summary>
    /// <param name="purpose">The operation the signature is bound to.</param>
    /// <param name="payload">The operation's own bytes.</param>
    /// <returns>A 32-byte digest.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="purpose"/> is not a defined value.</exception>
    public static byte[] CreateDigest(AnchorPurpose purpose, ReadOnlySpan<byte> payload)
    {
        byte[] label = Encoding.ASCII.GetBytes(DomainLabel);
        byte[] purposeLabel = Encoding.ASCII.GetBytes(GetPurposeLabel(purpose));

        Sha256Digest digest = new Sha256Digest();
        digest.BlockUpdate(label, 0, label.Length);
        digest.Update(Separator);
        digest.BlockUpdate(purposeLabel, 0, purposeLabel.Length);
        digest.Update(Separator);
        digest.BlockUpdate(payload);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }
}
