namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// Locates the real device attestation vectors, which live outside this repository.
/// </summary>
/// <remarks>
/// <para>
/// A device vector is not sample data. It carries a real device key, a real application
/// identity and its signing digest, so it is never committed here. The repository holds
/// the code that reads a vector; the vector itself is supplied by whoever runs the tests.
/// </para>
/// <para><b>Where the vectors are read from</b></para>
/// <para>
/// The root directory is resolved at run time, in this order:
/// </para>
/// <list type="number">
///   <item>
///     the <c>MOBILEATTEST_FIXTURES</c> environment variable, when it is set to a
///     non-empty value; otherwise
///   </item>
///   <item>
///     a per-user default beneath the current user's profile directory, built from path
///     segments rather than written out as one absolute string.
///   </item>
/// </list>
/// <para>
/// Nothing in the build copies files into the output directory, and no project file
/// references a fixture path. Pointing the environment variable at another directory is
/// the whole configuration.
/// </para>
/// <para><b>What the directory holds</b></para>
/// <code>
/// &lt;root&gt;/Apple/ios-app-attest.json     one enrollment and one assertion
/// &lt;root&gt;/Android/chain-*.pem           a key attestation certificate chain, leaf first
/// &lt;root&gt;/Roots/                        pinned roots, supplied by whoever runs the tests
/// </code>
/// <para>
/// The <c>Roots</c> directory is a location, not a shipped list. This library pins no root
/// and downloads none; a root reaches it as caller-supplied text, and the same rule holds
/// for the tests.
/// </para>
/// <para><b>When a vector is absent</b></para>
/// <para>
/// Tests that need one are marked <see cref="FixtureFactAttribute"/> or
/// <see cref="FixtureTheoryAttribute"/>. On a machine without the vectors they are
/// reported as skipped, each naming the full path it looked for, so an absent vector reads
/// as an absent vector and never as a pass. Every other test runs on a clean clone.
/// </para>
/// </remarks>
public static class TestVectors
{
    /// <summary>The environment variable that overrides the default root directory.</summary>
    public const string EnvironmentVariableName = "MOBILEATTEST_FIXTURES";

    /// <summary>The Apple App Attest vector, relative to the root directory.</summary>
    public const string AppleVectorPath = "Apple/ios-app-attest.json";

    /// <summary>
    /// Apple's App Attest root, relative to the root directory.
    /// </summary>
    /// <remarks>
    /// Unlike the Android side, the certificate above this one does not exist: this is the
    /// self-signed root Apple publishes, and the attestation object carries the intermediate
    /// below it in its own <c>x5c</c>. So an Apple chain can be validated all the way to a
    /// genuine platform root, and the tests that do so say exactly that.
    /// <para>
    /// It is a public certificate, not device material. It lives outside the repository only
    /// because one rule covers every fixture, and because this library ships no root: a root
    /// reaches it as a caller-supplied parameter, in a test exactly as in production.
    /// </para>
    /// </remarks>
    public const string AppleRootPath = "Apple/roots/apple-app-attestation-root-ca.pem";

    /// <summary>The Android key attestation leaf certificate, relative to the root directory.</summary>
    public const string AndroidLeafPath = "Android/chain-0-leaf.pem";

    /// <summary>The intermediate that issued the leaf, relative to the root directory.</summary>
    public const string AndroidIntermediatePath = "Android/chain-1-intermediate.pem";

    /// <summary>
    /// The highest certificate the vector contains, relative to the root directory.
    /// </summary>
    /// <remarks>
    /// This is an intermediate, not a root: the certificate above it and the Google hardware
    /// attestation root above that were never supplied. Tests anchor here so that the chain
    /// engine can be exercised on real device material, and no test in this project claims
    /// that a device chain reaches a genuine platform root.
    /// </remarks>
    public const string AndroidAnchorPath = "Android/chain-2-intermediate.pem";

    /// <summary>
    /// Google hardware attestation root, serial number <c>f92009e853b6b045</c>, relative to
    /// the root directory.
    /// </summary>
    /// <remarks>
    /// Published by Google, and one of exactly two anchors in the active set. See
    /// <see cref="AndroidRootKeyAttestationCa1Path"/> for why both matter.
    /// </remarks>
    public const string AndroidRoot2022Path = "Android/roots/google-attestation-root-2022.pem";

    /// <summary>
    /// Google <c>Key Attestation CA1</c>, the newer anchor, relative to the root directory.
    /// </summary>
    /// <remarks>
    /// Issued in July 2025 and signing attestation chains since February 2026. A deployment
    /// that pins only the older root refuses devices whose chains reach this one, which is a
    /// failure that arrives with new hardware rather than at integration time.
    /// </remarks>
    public const string AndroidRootKeyAttestationCa1Path = "Android/roots/google-key-attestation-ca1.pem";

    /// <summary>The directory holding caller-supplied pinned roots, relative to the root directory.</summary>
    public const string RootsDirectoryPath = "Roots";

    private const string SkipReasonPrefix = "fixture not found at ";

    /// <summary>
    /// The resolved root directory. This is a path, not a promise: it is returned whether
    /// or not the directory exists.
    /// </summary>
    public static string Root => ResolveRoot(
        Environment.GetEnvironmentVariable(EnvironmentVariableName),
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));

    /// <summary>
    /// Applies the resolution order to explicit inputs, so the rule can be tested without
    /// changing the environment of the running process.
    /// </summary>
    /// <param name="environmentValue">The environment variable's value, or null when unset.</param>
    /// <param name="profileDirectory">The current user's profile directory.</param>
    /// <returns>The root directory the vectors are expected under.</returns>
    public static string ResolveRoot(string? environmentValue, string profileDirectory)
    {
        if (!string.IsNullOrWhiteSpace(environmentValue))
        {
            return environmentValue!;
        }

        // Built from segments against the profile directory. The machine-specific part
        // comes from the environment, so no absolute path is written into the repository.
        return Path.Combine(profileDirectory, ".engram", "projects", "MobileAttest", "fixtures");
    }

    /// <summary>Resolves a vector path relative to <see cref="Root"/>.</summary>
    /// <param name="relativePath">A path relative to the root, using forward slashes.</param>
    /// <returns>The absolute path the vector is expected at.</returns>
    public static string Resolve(string relativePath)
    {
        ArgumentNullException.ThrowIfNull(relativePath);

        string[] segments = relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        string[] parts = new string[segments.Length + 1];
        parts[0] = Root;
        segments.CopyTo(parts, 1);
        return Path.Combine(parts);
    }

    /// <summary>
    /// Builds the reason a test is skipped, or null when every required vector is present.
    /// </summary>
    /// <param name="relativePaths">The vectors the test needs, relative to the root.</param>
    /// <returns>
    /// The skip reason, naming the first missing path in full, or null when nothing is
    /// missing. The full path is in the reason on purpose: "fixture not found" alone sends
    /// the reader looking for a directory the message could have named.
    /// </returns>
    public static string? SkipReasonFor(params string[] relativePaths)
    {
        ArgumentNullException.ThrowIfNull(relativePaths);

        foreach (string relativePath in relativePaths)
        {
            string resolved = Resolve(relativePath);

            if (!File.Exists(resolved) && !Directory.Exists(resolved))
            {
                return SkipReasonPrefix + resolved;
            }
        }

        return null;
    }
}
