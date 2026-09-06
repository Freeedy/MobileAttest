using System.Text;
using System.Text.Json;

namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// Reads the Apple App Attest vector file and pulls out the two authenticator data blobs
/// the parser tests need.
/// </summary>
/// <remarks>
/// <para>
/// The expected values a test compares against come from this file's own fields -- the
/// team identifier, the bundle identifier and the key identifier are read, never written
/// into the test source. A test that hardcoded them would put a real application identity
/// into a public repository, and it would also stop being a test of the vector.
/// </para>
/// <para>
/// <b>This is not the library's CBOR decoder.</b> The attestation and assertion objects
/// are CBOR, and which decoder the library will use is still an open decision, so nothing
/// general is written here. This reader scans for one known map key and reads the byte
/// string that follows it, which is enough to reach <c>authData</c> in a file of a shape
/// we already have in front of us, and is useless for anything else. It lives in the test
/// project and the library does not reference it.
/// </para>
/// </remarks>
public sealed class AppleVectorFile
{
    private const string AttestationAuthenticatorDataKey = "authData";
    private const string AssertionAuthenticatorDataKey = "authenticatorData";

    private AppleVectorFile(
        string path,
        string teamId,
        string bundleId,
        string keyIdBase64,
        byte[] attestationObject,
        byte[] attestationChallenge,
        byte[] assertionObject,
        byte[] assertionClientDataHash)
    {
        Path = path;
        TeamId = teamId;
        BundleId = bundleId;
        KeyIdBase64 = keyIdBase64;
        AttestationObject = attestationObject;
        AttestationChallenge = attestationChallenge;
        AssertionObject = assertionObject;
        AssertionClientDataHash = assertionClientDataHash;
    }

    /// <summary>The absolute path the vector was read from.</summary>
    public string Path { get; }

    /// <summary>The team identifier the vector declares.</summary>
    public string TeamId { get; }

    /// <summary>The bundle identifier the vector declares.</summary>
    public string BundleId { get; }

    /// <summary>The key identifier the vector declares, base64 encoded.</summary>
    public string KeyIdBase64 { get; }

    /// <summary>The raw CBOR attestation object.</summary>
    public byte[] AttestationObject { get; }

    /// <summary>
    /// The challenge the attestation was made over, as the capture recorded it.
    /// </summary>
    /// <remarks>
    /// Read from the vector rather than written down here, like every other expected value.
    /// The nonce inside the credential certificate is derived from this, so a test that
    /// supplied its own challenge would be asserting a mismatch rather than a match.
    /// </remarks>
    public byte[] AttestationChallenge { get; }

    /// <summary>The raw CBOR assertion object.</summary>
    public byte[] AssertionObject { get; }

    /// <summary>
    /// The client data hash the assertion was made over, as the capture recorded it.
    /// </summary>
    /// <remarks>
    /// Read from the vector, like every other expected value. The signature covers the
    /// authenticator data concatenated with this digest, so a test that invented its own
    /// would be asserting a rejection it caused rather than one the vector carries.
    /// </remarks>
    public byte[] AssertionClientDataHash { get; }

    /// <summary>The authenticator data carried by the attestation object.</summary>
    public byte[] AttestationAuthenticatorData =>
        ReadByteStringAfterKey(AttestationObject, AttestationAuthenticatorDataKey);

    /// <summary>The authenticator data carried by the assertion object.</summary>
    public byte[] AssertionAuthenticatorData =>
        ReadByteStringAfterKey(AssertionObject, AssertionAuthenticatorDataKey);

    /// <summary>Loads the vector from the resolved fixture location.</summary>
    /// <returns>The parsed vector.</returns>
    public static AppleVectorFile Load()
    {
        string path = TestVectors.Resolve(TestVectors.AppleVectorPath);
        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));
        JsonElement root = document.RootElement;

        JsonElement meta = Property(root, "meta");
        JsonElement attestation = Property(root, "attestation");
        JsonElement assertion = Property(root, "assertion");

        return new AppleVectorFile(
            path,
            Text(meta, "teamId"),
            Text(meta, "bundleId"),
            Text(root, "keyId"),
            Convert.FromBase64String(Text(attestation, "attestationObject_b64")),
            Convert.FromBase64String(Text(attestation, "challenge_b64")),
            Convert.FromBase64String(Text(assertion, "assertionObject_b64")),
            Convert.FromBase64String(Text(assertion, "clientDataHash_b64")));
    }

    private static JsonElement Property(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out JsonElement value))
        {
            throw new FormatException($"The vector has no '{name}' member.");
        }

        return value;
    }

    private static string Text(JsonElement parent, string name)
    {
        string? value = Property(parent, name).GetString();

        if (string.IsNullOrEmpty(value))
        {
            throw new FormatException($"The vector's '{name}' member is empty.");
        }

        return value;
    }

    /// <summary>
    /// Finds a definite-length text key in a CBOR map and returns the byte string that
    /// follows it.
    /// </summary>
    /// <remarks>
    /// The scan is over raw bytes rather than a decoded structure, so it insists on
    /// finding the key exactly once. Two matches would mean the pattern also occurred
    /// inside a certificate or a signature, and picking either one would silently make the
    /// test assert against the wrong bytes.
    /// </remarks>
    private static byte[] ReadByteStringAfterKey(byte[] cbor, string key)
    {
        // Major type 3, definite length encoded in the initial byte. Both keys used here
        // are shorter than 24 characters, which is what makes that encoding apply.
        if (key.Length >= 24)
        {
            throw new ArgumentOutOfRangeException(nameof(key), key, "The key is too long for a single-byte header.");
        }

        byte[] header = new byte[key.Length + 1];
        header[0] = (byte)(0x60 | key.Length);
        Encoding.ASCII.GetBytes(key).CopyTo(header, 1);

        int start = -1;

        for (int i = 0; i + header.Length < cbor.Length; i++)
        {
            if (!cbor.AsSpan(i, header.Length).SequenceEqual(header))
            {
                continue;
            }

            if (start >= 0)
            {
                throw new FormatException($"The key '{key}' occurs more than once in the object.");
            }

            start = i;
        }

        if (start < 0)
        {
            throw new FormatException($"The key '{key}' was not found in the object.");
        }

        int position = start + header.Length;
        byte initial = cbor[position++];
        int length;

        // Major type 2, in the three definite-length forms an App Attest object uses.
        if (initial is >= 0x40 and <= 0x57)
        {
            length = initial - 0x40;
        }
        else if (initial == 0x58)
        {
            length = cbor[position++];
        }
        else if (initial == 0x59)
        {
            length = (cbor[position] << 8) | cbor[position + 1];
            position += 2;
        }
        else
        {
            throw new FormatException($"The value after '{key}' is not a definite-length byte string.");
        }

        if (length > cbor.Length - position)
        {
            throw new FormatException($"The byte string after '{key}' runs past the end of the object.");
        }

        return cbor.AsSpan(position, length).ToArray();
    }
}
