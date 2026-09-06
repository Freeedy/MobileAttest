namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// A clock that does not move, so a test can state the instant it is testing at.
/// </summary>
/// <remarks>
/// <para>
/// Every test here that touches a certificate's validity dates pins the clock. The
/// vectors this project verifies against are short lived -- one intermediate in the
/// Android chain is valid for twelve days -- so a test written against the real clock
/// passes today, fails on a date nobody wrote down, and fails looking exactly like a
/// defect in the validator rather than an expired input.
/// </para>
/// <para>
/// <see cref="TimeProvider"/> is the platform's own abstraction and is in the box on
/// .NET 8, so pinning the clock costs a derived class here and no dependency at all.
/// </para>
/// </remarks>
public sealed class FixedTimeProvider : TimeProvider
{
    private readonly DateTimeOffset _now;

    /// <summary>Creates a clock stopped at an instant.</summary>
    /// <param name="now">The instant the clock reports.</param>
    public FixedTimeProvider(DateTimeOffset now) => _now = now;

    /// <summary>Creates a clock stopped at a UTC instant.</summary>
    /// <param name="year">The year.</param>
    /// <param name="month">The month.</param>
    /// <param name="day">The day.</param>
    /// <param name="hour">The hour.</param>
    /// <param name="minute">The minute.</param>
    /// <param name="second">The second.</param>
    /// <returns>The stopped clock.</returns>
    public static FixedTimeProvider AtUtc(
        int year,
        int month,
        int day,
        int hour = 0,
        int minute = 0,
        int second = 0) =>
        new(new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero));

    /// <inheritdoc />
    public override DateTimeOffset GetUtcNow() => _now;
}
