using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace MobileAttest.Android;

/// <summary>
/// The status source used when the caller supplied none. It answers
/// <see cref="KeyStatus.Unknown"/> for every key and touches no network.
/// </summary>
/// <remarks>
/// <para><b>It reports; it does not decide</b></para>
/// <para>
/// This type takes no position on whether an unverifiable key should be accepted. It states
/// that nothing is known, and <see cref="RevocationPolicy"/> -- which the caller selects --
/// turns that into an outcome:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <see cref="RevocationPolicy.Skip"/> with this source: revocation is not checked at
///       all, which is the caller's explicit choice rather than an accident.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="RevocationPolicy.HardFail"/> with this source: <b>every</b> verification
///       is refused with
///       <see cref="Abstractions.AttestationFailureReason.RevocationStatusUnavailable"/>.
///       That combination is a misconfiguration, and it fails loudly on the first request
///       instead of quietly accepting keys nobody checked.
///     </description>
///   </item>
/// </list>
/// <para>
/// Answering <see cref="KeyStatus.Valid"/> here would have been the convenient choice and the
/// wrong one: it would report that a list had been consulted when none had.
/// </para>
/// </remarks>
public sealed class NullKeyStatusSource : IKeyStatusSource
{
    /// <summary>
    /// The shared instance. The type holds no state, so one instance serves every verifier.
    /// </summary>
    public static readonly NullKeyStatusSource Instance = new NullKeyStatusSource();

    private static readonly Task<KeyStatus> UnknownResult = Task.FromResult(KeyStatus.Unknown);

    /// <inheritdoc />
    /// <remarks>
    /// The token is accepted to satisfy the contract and is not observed: there is no I/O
    /// here to abandon, and throwing on a cancelled token would introduce a failure the
    /// caller's own source might not have.
    /// </remarks>
    public Task<KeyStatus> GetStatusAsync(
        BigInteger serialNumber,
        CancellationToken cancellationToken = default) => UnknownResult;
}
