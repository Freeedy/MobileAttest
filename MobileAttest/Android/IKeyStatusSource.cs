using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace MobileAttest.Android;

/// <summary>
/// What a status source was able to establish about one attestation key.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Unknown"/> is deliberately the zero value. A source that fails to answer, a
/// response that will not parse and a source that was never configured all end here, so the
/// value a caller gets when nothing worked is the one that asserts nothing.
/// </para>
/// <para>
/// <see cref="Unknown"/> is never read as <see cref="Valid"/>. What happens to it is
/// decided by <see cref="RevocationPolicy"/>, which the caller selects.
/// </para>
/// </remarks>
public enum KeyStatus
{
    /// <summary>
    /// The status could not be established. This asserts nothing about the key: it is not a
    /// weaker form of <see cref="Valid"/>.
    /// </summary>
    Unknown = 0,

    /// <summary>The source answered, and the key is not listed as revoked or suspended.</summary>
    Valid = 1,

    /// <summary>The source lists the key as revoked.</summary>
    Revoked = 2,

    /// <summary>The source lists the key as suspended.</summary>
    Suspended = 3,
}

/// <summary>
/// What to do when the status of an attestation key cannot be established.
/// </summary>
/// <remarks>
/// <para><b>There is no default, and the library does not choose one</b></para>
/// <para>
/// Both behaviours exist and the choice is the caller's.
/// <see cref="AndroidAttestOptions.RevocationPolicy"/> is nullable and
/// <see cref="AndroidAttestOptions.Validate"/> refuses a configuration that left it unset,
/// so a policy nobody selected cannot quietly become the lenient one.
/// </para>
/// <para>
/// Zero is left unnamed for the same reason. An enumeration whose default value is a working
/// policy hands out that policy to every field, array element and deserialised object that
/// was never assigned, and no test would see the difference.
/// </para>
/// <list type="table">
///   <listheader>
///     <term>Value</term>
///     <description>Behaviour</description>
///   </listheader>
///   <item>
///     <term><see cref="Skip"/></term>
///     <description>
///       <see cref="KeyStatus.Unknown"/> is accepted and verification continues.
///       <see cref="KeyStatus.Revoked"/> and <see cref="KeyStatus.Suspended"/> are still
///       refused.
///     </description>
///   </item>
///   <item>
///     <term><see cref="HardFail"/></term>
///     <description>
///       <see cref="KeyStatus.Unknown"/> is refused with
///       <see cref="Abstractions.AttestationFailureReason.RevocationStatusUnavailable"/>.
///     </description>
///   </item>
/// </list>
/// <para>
/// A revoked or suspended key is refused under <b>both</b> policies. The policy decides what
/// silence means, never what a positive answer means.
/// </para>
/// </remarks>
public enum RevocationPolicy
{
    /// <summary>
    /// Accept a key whose status could not be established, and keep verifying.
    /// </summary>
    /// <remarks>
    /// This is the choice for a deployment that runs without network access, or that treats
    /// revocation as advisory. It weakens nothing else: a key the source reports as revoked
    /// or suspended is still refused.
    /// </remarks>
    Skip = 1,

    /// <summary>
    /// Refuse a key whose status could not be established.
    /// </summary>
    /// <remarks>
    /// Refusal is total, and that is the point. Selecting this without configuring an
    /// <see cref="IKeyStatusSource"/> refuses every verification, because the only source
    /// then in play answers <see cref="KeyStatus.Unknown"/> to everything. That failure is
    /// immediate and visible rather than silent.
    /// </remarks>
    HardFail = 2,
}

/// <summary>
/// Answers what a revocation status list says about one attestation key.
/// </summary>
/// <remarks>
/// <para><b>Why this is an interface</b></para>
/// <para>
/// Checking a key's status is a network operation, and a verifier that performed it inline
/// could not be tested without one. Behind this abstraction the interesting cases -- revoked,
/// suspended, an endpoint that does not answer -- are reachable with a test double, and no
/// test in this project depends on a service being reachable.
/// </para>
/// <para><b>Nothing here is consulted unless the caller supplies it</b></para>
/// <para>
/// This library creates no <see cref="System.Net.Http.HttpClient"/> and holds no address.
/// A caller who supplies no source gets <see cref="NullKeyStatusSource"/>, which answers
/// <see cref="KeyStatus.Unknown"/> and touches no network.
/// </para>
/// <para><b>The serial number leaves the process</b></para>
/// <para>
/// An implementation that queries a remote service sends the device's certificate serial
/// number to it, which is a privacy decision about the caller's users. That is why the
/// source is supplied rather than assumed, and why the default one asks nobody anything.
/// </para>
/// </remarks>
public interface IKeyStatusSource
{
    /// <summary>
    /// Looks up the status of the attestation key identified by a certificate serial number.
    /// </summary>
    /// <param name="serialNumber">
    /// The serial number of the leaf certificate whose key is being verified, exactly as the
    /// certificate carries it.
    /// </param>
    /// <param name="cancellationToken">Abandons a lookup in progress.</param>
    /// <returns>
    /// What the source could establish. An implementation reports a failure it recovered from
    /// as <see cref="KeyStatus.Unknown"/> rather than by throwing: an unreachable status
    /// service must be able to become a policy decision, not an outage.
    /// </returns>
    Task<KeyStatus> GetStatusAsync(BigInteger serialNumber, CancellationToken cancellationToken = default);
}
