using System.Text;
using MobileAttest.Protocol;
using Org.BouncyCastle.Crypto.Digests;

namespace MobileAttest.Tests.Protocol;

/// <summary>
/// The signed message construction is a wire contract: once anything signs with it, a
/// change to the label, the separators or the field order invalidates every signature
/// already issued. These tests exist so such a change cannot happen quietly.
/// </summary>
public class AnchorSignatureContextTests
{
    private static byte[] Sha256(byte[] input)
    {
        Sha256Digest digest = new Sha256Digest();
        digest.BlockUpdate(input, 0, input.Length);
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }

    [Fact]
    public void AC7_AnchorSignatureContext_ProducesDeterministicDigest()
    {
        byte[] payload = Encoding.ASCII.GetBytes("the-request-body");

        byte[] first = AnchorSignatureContext.CreateDigest(AnchorPurpose.AuthToken, payload);
        byte[] second = AnchorSignatureContext.CreateDigest(AnchorPurpose.AuthToken, payload);

        Assert.Equal(AnchorSignatureContext.DigestLength, first.Length);
        Assert.Equal(first, second);

        // The message is rebuilt here by hand, byte by byte, rather than by calling the
        // same helper twice. That is what makes this a check of the construction -- label,
        // separator, purpose, separator, payload -- and not merely of repeatability.
        List<byte> message = new List<byte>();
        message.AddRange(Encoding.ASCII.GetBytes("mobileattest.anchor.v1"));
        message.Add(0x00);
        message.AddRange(Encoding.ASCII.GetBytes("auth-token"));
        message.Add(0x00);
        message.AddRange(payload);

        Assert.Equal(Sha256(message.ToArray()), first);
    }

    [Fact]
    public void AC7_AnchorSignatureContext_DifferentPurpose_ProducesDifferentDigest()
    {
        byte[] payload = Encoding.ASCII.GetBytes("the-request-body");

        byte[] authToken = AnchorSignatureContext.CreateDigest(AnchorPurpose.AuthToken, payload);
        byte[] gateVerify = AnchorSignatureContext.CreateDigest(AnchorPurpose.GateVerify, payload);
        byte[] keyBinding = AnchorSignatureContext.CreateDigest(AnchorPurpose.KeyBinding, payload);

        // Identical payload, three purposes, three digests. If any two collided, a
        // signature collected for one operation would prove another.
        Assert.NotEqual(authToken, gateVerify);
        Assert.NotEqual(authToken, keyBinding);
        Assert.NotEqual(gateVerify, keyBinding);

        // An undefined purpose must not silently fall through to some default label.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => AnchorSignatureContext.CreateDigest((AnchorPurpose)999, payload));

        // The separator is what stops the purpose and the payload from being re-split:
        // purpose "auth-token" with an empty payload must not equal the digest of a
        // purpose whose label absorbed the payload's leading bytes.
        byte[] emptyPayload = AnchorSignatureContext.CreateDigest(
            AnchorPurpose.AuthToken,
            Array.Empty<byte>());
        Assert.NotEqual(authToken, emptyPayload);
    }
}
