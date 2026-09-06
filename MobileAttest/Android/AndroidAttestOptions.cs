using System;
using System.Collections.Generic;
using Org.BouncyCastle.X509;

namespace MobileAttest.Android;

/// <summary>
/// The caller's Android Key Attestation policy. Every value here is configuration: this
/// library hardcodes no package, no signing digest and no root certificate.
/// </summary>
public sealed class AndroidAttestOptions
{
    /// <summary>
    /// The application signing certificate digests that are accepted, as read from the
    /// attestation application identifier. A digest absent from this list is rejected.
    /// </summary>
    /// <remarks>
    /// Each entry is hexadecimal, upper or lower case, with no separators -- the form
    /// <c>apksigner</c> and <c>keytool</c> print. The record carries these as raw octets, so
    /// the text is decoded once and the comparison is made over bytes;
    /// <see cref="Validate"/> rejects an entry that is not hexadecimal, because an entry that
    /// can never match is an allowlist one application shorter than its author believes.
    /// </remarks>
    public IReadOnlyCollection<string> AllowedSignatureDigests { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Whether the key must live in StrongBox rather than a trusted execution environment.
    /// </summary>
    /// <remarks>
    /// Defaults to <see langword="false"/>. StrongBox is not present on every Android
    /// device, so requiring it is a deployment decision that excludes hardware, not a
    /// default this library makes on the caller's behalf. A trusted execution environment
    /// remains the minimum either way.
    /// </remarks>
    public bool RequireStrongBox { get; set; }

    /// <summary>
    /// The pinned Google hardware attestation root certificates a chain must terminate
    /// in. Roots are supplied by the caller and are never fetched at verification time.
    /// </summary>
    public IReadOnlyList<X509Certificate> PinnedRootCertificates { get; set; } =
        Array.Empty<X509Certificate>();

    /// <summary>
    /// Rejects a configuration that would make verification meaningless.
    /// </summary>
    /// <remarks>
    /// Checks run in declaration order -- signing digests, then pinned roots -- and the
    /// first violation stops validation.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The configuration is incomplete.</exception>
    public void Validate()
    {
        if (AllowedSignatureDigests is null || AllowedSignatureDigests.Count == 0)
        {
            throw new InvalidOperationException(
                $"{nameof(AndroidAttestOptions)}.{nameof(AllowedSignatureDigests)} must list at " +
                "least one digest; an empty allowlist would accept every application.");
        }

        int index = 0;

        foreach (string digest in AllowedSignatureDigests)
        {
            if (digest is null || !TryParseSignatureDigest(digest, out _))
            {
                // The offending entry is named by position rather than by value, which is
                // enough to find it in a configuration file and puts no application identity
                // into an exception message.
                throw new InvalidOperationException(
                    $"{nameof(AndroidAttestOptions)}.{nameof(AllowedSignatureDigests)} holds an " +
                    $"entry at index {index} that is not hexadecimal. Such an entry matches no " +
                    "device and would silently shorten the allowlist.");
            }

            index++;
        }

        if (PinnedRootCertificates is null || PinnedRootCertificates.Count == 0)
        {
            throw new InvalidOperationException(
                $"{nameof(AndroidAttestOptions)}.{nameof(PinnedRootCertificates)} must contain at " +
                "least one root; without a pinned root a chain is validated against nothing.");
        }
    }

    /// <summary>
    /// Decodes one entry of <see cref="AllowedSignatureDigests"/> into the octets the
    /// attestation record carries.
    /// </summary>
    /// <param name="text">The configured entry.</param>
    /// <param name="digest">The decoded octets, or <see langword="null"/> when the entry was
    /// not hexadecimal.</param>
    /// <returns>Whether the entry decoded.</returns>
    /// <remarks>
    /// Written out rather than delegated to <c>Convert.FromHexString</c> because that method
    /// reports a bad entry by throwing, and this runs inside a comparison loop where an
    /// exception would be control flow. The rule the format defines lives here, next to the
    /// property that declares it, so the policy and <see cref="Validate"/> cannot drift into
    /// accepting different things.
    /// </remarks>
    internal static bool TryParseSignatureDigest(string text, out byte[]? digest)
    {
        digest = null;

        if (string.IsNullOrEmpty(text) || text.Length % 2 != 0)
        {
            return false;
        }

        byte[] value = new byte[text.Length / 2];

        for (int i = 0; i < value.Length; i++)
        {
            if (!TryReadNibble(text[i * 2], out int high) ||
                !TryReadNibble(text[(i * 2) + 1], out int low))
            {
                return false;
            }

            value[i] = (byte)((high << 4) | low);
        }

        digest = value;
        return true;
    }

    private static bool TryReadNibble(char character, out int value)
    {
        if (character >= '0' && character <= '9')
        {
            value = character - '0';
            return true;
        }

        if (character >= 'a' && character <= 'f')
        {
            value = character - 'a' + 10;
            return true;
        }

        if (character >= 'A' && character <= 'F')
        {
            value = character - 'A' + 10;
            return true;
        }

        value = 0;
        return false;
    }
}
