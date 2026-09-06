using MobileAttest.Android;
using MobileAttest.Apple;

namespace MobileAttest.Tests.Configuration;

/// <summary>
/// Root pinning is the rule both platforms share, so it is guarded once for both.
/// </summary>
public class PinnedRootRequirementTests
{
    [Fact]
    public void AC7_Options_NoPinnedRoot_IsRejected()
    {
        // Otherwise complete Apple configuration, missing only the pinned roots.
        AppleAttestOptions apple = new AppleAttestOptions
        {
            TeamId = "EXAMPLETEAM",
            BundleIdAllowlist = new[] { "com.example.app" },
        };

        InvalidOperationException appleError =
            Assert.Throws<InvalidOperationException>(() => apple.Validate());
        Assert.Contains(
            nameof(AppleAttestOptions.PinnedRootCertificates),
            appleError.Message,
            StringComparison.Ordinal);

        // Otherwise complete Android configuration, missing only the pinned roots.
        AndroidAttestOptions android = new AndroidAttestOptions
        {
            AllowedSignatureDigests = new[] { "0f1e2d3c4b5a69788796a5b4c3d2e1f0" },
        };

        InvalidOperationException androidError =
            Assert.Throws<InvalidOperationException>(() => android.Validate());
        Assert.Contains(
            nameof(AndroidAttestOptions.PinnedRootCertificates),
            androidError.Message,
            StringComparison.Ordinal);
    }
}
