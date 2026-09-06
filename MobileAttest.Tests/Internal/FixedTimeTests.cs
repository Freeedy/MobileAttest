using MobileAttest.Internal;

namespace MobileAttest.Tests.Internal;

/// <summary>
/// Guards the constant-time comparison wrapper. Timing behaviour itself is not asserted
/// here -- that is not something a unit test can measure reliably. What is asserted is
/// that the wrapper answers correctly, because a constant-time comparison that returns
/// the wrong answer is worse than a fast one that returns the right answer.
/// </summary>
public class FixedTimeTests
{
    [Fact]
    public void AC3_FixedTimeEquals_EqualAndDifferentInputs_ReturnExpected()
    {
        byte[] value = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] sameContentDifferentInstance = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] differsInFirstByte = new byte[] { 0xFF, 0x02, 0x03, 0x04 };
        byte[] differsInLastByte = new byte[] { 0x01, 0x02, 0x03, 0xFF };

        Assert.True(FixedTime.FixedTimeEquals(value, value));
        Assert.True(FixedTime.FixedTimeEquals(value, sameContentDifferentInstance));
        Assert.False(FixedTime.FixedTimeEquals(value, differsInFirstByte));
        Assert.False(FixedTime.FixedTimeEquals(value, differsInLastByte));
    }

    [Fact]
    public void AC3_FixedTimeEquals_DifferentLengths_ReturnsFalse()
    {
        byte[] shorter = new byte[] { 0x01, 0x02, 0x03 };
        byte[] longerWithSamePrefix = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        // A length mismatch is an answer, not an error: callers compare attacker-supplied
        // material and must not need a try/catch around every comparison.
        Assert.False(FixedTime.FixedTimeEquals(shorter, longerWithSamePrefix));
        Assert.False(FixedTime.FixedTimeEquals(longerWithSamePrefix, shorter));
        Assert.False(FixedTime.FixedTimeEquals(shorter, Array.Empty<byte>()));
        Assert.False(FixedTime.FixedTimeEquals(null, shorter));
        Assert.False(FixedTime.FixedTimeEquals(shorter, null));
    }
}
