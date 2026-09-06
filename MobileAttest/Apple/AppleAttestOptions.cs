using System;
using System.Collections.Generic;
using Org.BouncyCastle.X509;

namespace MobileAttest.Apple;

/// <summary>
/// The caller's Apple App Attest policy. Every value here is configuration: this library
/// hardcodes no team, no bundle identifier and no root certificate.
/// </summary>
public sealed class AppleAttestOptions
{
    /// <summary>
    /// The Apple team identifier the attestation must be bound to. Together with the
    /// bundle identifier it forms the application identity that is hashed and compared
    /// against the relying-party identifier hash.
    /// </summary>
    public string TeamId { get; set; } = string.Empty;

    /// <summary>
    /// The bundle identifiers that are accepted. An attestation whose bundle identifier
    /// is absent from this list is rejected.
    /// </summary>
    public IReadOnlyCollection<string> BundleIdAllowlist { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Whether a development-environment key is rejected. Defaults to
    /// <see langword="true"/>, so a development key is refused unless the caller decides
    /// otherwise. The environment is read from the AAGUID, never from client metadata.
    /// </summary>
    public bool RequireProduction { get; set; } = true;

    /// <summary>
    /// The pinned Apple root certificates a chain must terminate in. Roots are supplied
    /// by the caller and are never fetched at verification time.
    /// </summary>
    public IReadOnlyList<X509Certificate> PinnedRootCertificates { get; set; } =
        Array.Empty<X509Certificate>();

    /// <summary>
    /// Rejects a configuration that would make verification meaningless.
    /// </summary>
    /// <remarks>
    /// Checks run in declaration order -- team identifier, then allowlist, then pinned
    /// roots -- and the first violation stops validation. Each of these omissions is
    /// silent at runtime if left unchecked: an empty allowlist accepts every application,
    /// and an empty root list leaves nothing for a chain to be pinned to.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The configuration is incomplete.</exception>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(TeamId))
        {
            throw new InvalidOperationException(
                $"{nameof(AppleAttestOptions)}.{nameof(TeamId)} must be set.");
        }

        if (BundleIdAllowlist is null || BundleIdAllowlist.Count == 0)
        {
            throw new InvalidOperationException(
                $"{nameof(AppleAttestOptions)}.{nameof(BundleIdAllowlist)} must list at least one " +
                "bundle identifier; an empty allowlist would accept every application.");
        }

        if (PinnedRootCertificates is null || PinnedRootCertificates.Count == 0)
        {
            throw new InvalidOperationException(
                $"{nameof(AppleAttestOptions)}.{nameof(PinnedRootCertificates)} must contain at " +
                "least one root; without a pinned root a chain is validated against nothing.");
        }
    }
}
