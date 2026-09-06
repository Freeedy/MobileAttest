using MobileAttest.Apple;

namespace MobileAttest.Tests.Apple;

/// <summary>
/// Configuration that is left incomplete must fail loudly at validation, not quietly at
/// verification. These tests pin the omissions that would otherwise weaken the check
/// without producing any visible error.
/// </summary>
public class AppleAttestOptionsTests
{
    [Fact]
    public void AC7_AppleAttestOptions_EmptyTeamId_IsRejected()
    {
        AppleAttestOptions missing = new AppleAttestOptions
        {
            TeamId = string.Empty,
            BundleIdAllowlist = new[] { "com.example.app" },
        };

        InvalidOperationException error =
            Assert.Throws<InvalidOperationException>(() => missing.Validate());
        Assert.Contains(nameof(AppleAttestOptions.TeamId), error.Message, StringComparison.Ordinal);

        // Whitespace is not a team identifier either.
        AppleAttestOptions blank = new AppleAttestOptions
        {
            TeamId = "   ",
            BundleIdAllowlist = new[] { "com.example.app" },
        };

        Assert.Throws<InvalidOperationException>(() => blank.Validate());
    }

    [Fact]
    public void AC7_AppleAttestOptions_EmptyBundleIdAllowlist_IsRejected()
    {
        AppleAttestOptions options = new AppleAttestOptions
        {
            TeamId = "EXAMPLETEAM",
            BundleIdAllowlist = Array.Empty<string>(),
        };

        // An empty allowlist is not "allow nothing", it is "compare against nothing" --
        // which is how every application ends up accepted.
        InvalidOperationException error =
            Assert.Throws<InvalidOperationException>(() => options.Validate());
        Assert.Contains(
            nameof(AppleAttestOptions.BundleIdAllowlist),
            error.Message,
            StringComparison.Ordinal);
    }
}
