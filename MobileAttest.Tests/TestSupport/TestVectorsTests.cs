namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// Tests for the vector locator itself: where it looks, and what it says when it finds
/// nothing.
/// </summary>
public class TestVectorsTests
{
    [Fact]
    public void AC4_TestVectors_MissingDirectory_ReportsPathInReason()
    {
        const string missing = "Apple/no-such-vector.json";

        string? reason = TestVectors.SkipReasonFor(missing);

        Assert.NotNull(reason);

        // A skip that says only "fixture not found" sends the reader looking for a
        // directory the message could have named. The full path is the whole point.
        Assert.StartsWith("fixture not found at ", reason);
        Assert.Contains(TestVectors.Resolve(missing), reason);
        Assert.True(Path.IsPathRooted(TestVectors.Resolve(missing)));
    }

    [Fact]
    public void AC6_TestVectors_EnvironmentVariable_OverridesDefaultRoot()
    {
        string profile = Path.Combine(Path.GetTempPath(), "profile");
        string chosen = Path.Combine(Path.GetTempPath(), "vectors-elsewhere");

        // Resolution is exercised through explicit inputs rather than by mutating the
        // process environment, which would leak into whatever else is running in parallel.
        Assert.Equal(chosen, TestVectors.ResolveRoot(chosen, profile));

        // An unset or blank variable falls back rather than resolving to an empty path.
        Assert.NotEqual(string.Empty, TestVectors.ResolveRoot(null, profile));
        Assert.Equal(
            TestVectors.ResolveRoot(null, profile),
            TestVectors.ResolveRoot("   ", profile));
    }

    [Fact]
    public void AC6_TestVectors_DefaultRoot_IsBuiltFromProfileDirectory()
    {
        string profile = Path.Combine(Path.GetTempPath(), "some-profile");

        string root = TestVectors.ResolveRoot(null, profile);

        // The machine-specific part comes from the profile the caller supplies, so no
        // absolute path is fixed in the source and the same code resolves on any machine.
        Assert.StartsWith(profile + Path.DirectorySeparatorChar, root);
        Assert.Equal("fixtures", Path.GetFileName(root));
        Assert.Equal(
            TestVectors.ResolveRoot(null, profile),
            TestVectors.ResolveRoot(null, profile));
    }

    [FixtureFact(TestVectors.AppleVectorPath)]
    public void AC2_TestVectors_AppleVector_IsReadableAndWellFormed()
    {
        AppleVectorFile vector = AppleVectorFile.Load();

        Assert.True(File.Exists(vector.Path));
        Assert.StartsWith(TestVectors.Root, vector.Path);

        // The fields a later test compares against have to be here, or those tests would
        // be asserting against defaults.
        Assert.NotEmpty(vector.TeamId);
        Assert.NotEmpty(vector.BundleId);
        Assert.NotEmpty(vector.KeyIdBase64);
        Assert.NotEmpty(vector.AttestationObject);
        Assert.NotEmpty(vector.AssertionObject);

        // Both objects are CBOR maps, and both carry authenticator data that can be
        // reached. Reading them here means a malformed vector fails as a malformed vector
        // instead of as a parser defect somewhere else.
        Assert.Equal(0xA3, vector.AttestationObject[0]);
        Assert.Equal(0xA2, vector.AssertionObject[0]);
        Assert.NotEmpty(vector.AttestationAuthenticatorData);
        Assert.Equal(37, vector.AssertionAuthenticatorData.Length);
    }
}
