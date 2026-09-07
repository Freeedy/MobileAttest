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
    /// What to do when the status of an attestation key cannot be established. There is no
    /// default: the caller selects one, and <see cref="Validate"/> rejects a configuration
    /// that did not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The property is nullable so that "not selected" is a state the type can hold and
    /// report. Were it a plain
    /// <see cref="MobileAttest.Android.RevocationPolicy"/>, a caller who never assigned it
    /// would receive whichever value happened to be zero, and would be running a revocation
    /// policy nobody chose -- the silent configuration this library exists to refuse. It is
    /// the same rule that makes an unpinned root a rejection rather than a fallback.
    /// </para>
    /// <para>
    /// The policy governs <see cref="KeyStatus.Unknown"/> only. A key reported as
    /// <see cref="KeyStatus.Revoked"/> or <see cref="KeyStatus.Suspended"/> is refused under
    /// either value.
    /// </para>
    /// </remarks>
    public RevocationPolicy? RevocationPolicy { get; set; }

    /// <summary>
    /// How long a key status answer stays usable before it is looked up again. Defaults to
    /// 24 hours.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Read by <see cref="CachedKeyStatusSource"/>, which is the only thing in this library
    /// that caches. A source used without that wrapper is called once per verification and
    /// this value does nothing.
    /// </para>
    /// <para>
    /// Every answer is cached for this long, <see cref="KeyStatus.Unknown"/> included. So the
    /// value is also the longest a status service can stay unreachable, recover, and go on
    /// being treated as unreachable. Shorten it where that matters more than the request
    /// volume it saves.
    /// </para>
    /// </remarks>
    public TimeSpan StatusCacheTtl { get; set; } = TimeSpan.FromHours(24);

    /// <summary>
    /// Rejects a configuration that would make verification meaningless.
    /// </summary>
    /// <remarks>
    /// Checks run in declaration order -- signing digests, then pinned roots, then the
    /// revocation policy -- and the first violation stops validation.
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

        if (RevocationPolicy is null)
        {
            // Named last because it is the newest requirement, and a caller upgrading into it
            // should see the two older faults first if they are also present.
            //
            // There is no default to fall back on. Choosing one here -- either one -- would be
            // this library deciding how much an unverifiable key is worth to a deployment it
            // knows nothing about, and the caller would never learn a decision had been made.
            throw new InvalidOperationException(
                $"{nameof(AndroidAttestOptions)}.{nameof(RevocationPolicy)} must be set to " +
                $"{nameof(MobileAttest.Android.RevocationPolicy.Skip)} or " +
                $"{nameof(MobileAttest.Android.RevocationPolicy.HardFail)}. There is no default: " +
                "whether a key whose revocation status cannot be established is accepted is the " +
                "caller's decision, not this library's.");
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
