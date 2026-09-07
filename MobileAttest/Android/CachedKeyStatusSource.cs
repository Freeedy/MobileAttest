using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace MobileAttest.Android;

/// <summary>
/// Holds each key's status for a while, so that verifying the same device twice does not ask
/// the source twice.
/// </summary>
/// <remarks>
/// <para><b>Why the wrapper rather than caching inside the source</b></para>
/// <para>
/// Caching is a decision about staleness, and staleness is the caller's risk to price. Keeping
/// it out here means the source stays a plain lookup that a test can count calls on, and a
/// caller who wants no caching at all simply does not wrap.
/// </para>
/// <para><b>Every answer is cached, including the unhelpful ones</b></para>
/// <para>
/// <see cref="KeyStatus.Unknown"/> is stored for the same period as any other answer. That is
/// what stops a status service that has stopped responding from being asked again on every
/// single verification, which is the load pattern that keeps such a service down. The cost is
/// stated plainly because it is real: after the service recovers, the stale
/// <see cref="KeyStatus.Unknown"/> stands until it expires, and under
/// <see cref="RevocationPolicy.HardFail"/> that is continued refusal. The time-to-live is
/// therefore also the worst-case recovery delay, and it is the caller's to set.
/// </para>
/// <para><b>What it does not do</b></para>
/// <para>
/// It does not collapse concurrent lookups. Several verifications of the same unseen serial
/// arriving together may each reach the source; the alternative is holding a lock across a
/// network call, which converts a slow service into a stalled application. Entries are removed
/// once expired, so what is retained is bounded by the distinct serial numbers seen inside one
/// time-to-live rather than by every serial ever verified.
/// </para>
/// </remarks>
public sealed class CachedKeyStatusSource : IKeyStatusSource
{
    /// <summary>
    /// How many entries may accumulate before expired ones are swept out.
    /// </summary>
    /// <remarks>
    /// A sweep walks the whole dictionary, so it is not done on every write. The threshold is
    /// deliberately not configuration: it changes how often a cheap piece of housekeeping runs
    /// and nothing a caller can observe, and every knob offered is a knob somebody has to
    /// understand.
    /// </remarks>
    private const int SweepThreshold = 1024;

    private readonly IKeyStatusSource _inner;
    private readonly TimeSpan _timeToLive;
    private readonly TimeProvider _timeProvider;

    private readonly ConcurrentDictionary<BigInteger, CacheEntry> _entries =
        new ConcurrentDictionary<BigInteger, CacheEntry>();

    /// <summary>Wraps a source, reading the clock from the system.</summary>
    /// <param name="inner">The source consulted when nothing usable is held.</param>
    /// <param name="timeToLive">How long an answer stays usable.</param>
    /// <exception cref="ArgumentNullException"><paramref name="inner"/> is <see langword="null"/>.</exception>
    public CachedKeyStatusSource(IKeyStatusSource inner, TimeSpan timeToLive)
        : this(inner, timeToLive, TimeProvider.System)
    {
    }

    /// <summary>Wraps a source, reading the clock from a supplied provider.</summary>
    /// <param name="inner">The source consulted when nothing usable is held.</param>
    /// <param name="timeToLive">
    /// How long an answer stays usable. Zero or a negative span means every lookup reaches the
    /// source, which is a working configuration rather than an error: it is "wrap it, but do
    /// not cache yet".
    /// </param>
    /// <param name="timeProvider">The clock expiry is measured against.</param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <remarks>
    /// The clock is injectable for the same reason it is on the verifier: expiry that can only
    /// be reached by waiting is expiry that is never tested, and a test that waited would be
    /// slow and would still be timing-dependent.
    /// </remarks>
    public CachedKeyStatusSource(IKeyStatusSource inner, TimeSpan timeToLive, TimeProvider timeProvider)
    {
        if (inner is null)
        {
            throw new ArgumentNullException(nameof(inner));
        }

        if (timeProvider is null)
        {
            throw new ArgumentNullException(nameof(timeProvider));
        }

        _inner = inner;
        _timeToLive = timeToLive;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">
    /// <paramref name="serialNumber"/> is <see langword="null"/>.
    /// </exception>
    public async Task<KeyStatus> GetStatusAsync(
        BigInteger serialNumber,
        CancellationToken cancellationToken = default)
    {
        if (serialNumber is null)
        {
            throw new ArgumentNullException(nameof(serialNumber));
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();

        if (_entries.TryGetValue(serialNumber, out CacheEntry? held) && held.ExpiresAt > now)
        {
            return held.Status;
        }

        KeyStatus status = await _inner.GetStatusAsync(serialNumber, cancellationToken).ConfigureAwait(false);

        // Written after the await, so a lookup that threw leaves nothing behind: an exception
        // is not an answer and must not be cached as one.
        _entries[serialNumber] = new CacheEntry(status, now + _timeToLive);

        if (_entries.Count > SweepThreshold)
        {
            RemoveExpired(now);
        }

        return status;
    }

    /// <summary>Drops entries that have expired.</summary>
    /// <remarks>
    /// Expired entries are already ignored on read, so this frees memory and changes no
    /// answer. An entry that expires between the snapshot and the removal is removed anyway,
    /// which costs one lookup and cannot produce a wrong result.
    /// </remarks>
    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (KeyValuePair<BigInteger, CacheEntry> entry in _entries)
        {
            if (entry.Value.ExpiresAt <= now)
            {
                _entries.TryRemove(entry.Key, out _);
            }
        }
    }

    /// <summary>One cached answer and the instant it stops being usable.</summary>
    private sealed class CacheEntry
    {
        internal CacheEntry(KeyStatus status, DateTimeOffset expiresAt)
        {
            Status = status;
            ExpiresAt = expiresAt;
        }

        internal KeyStatus Status { get; }

        internal DateTimeOffset ExpiresAt { get; }
    }
}
