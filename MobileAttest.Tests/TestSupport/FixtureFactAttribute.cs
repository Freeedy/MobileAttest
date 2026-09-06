namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// A fact that needs a real device vector, and that says so when the vector is absent.
/// </summary>
/// <remarks>
/// <para>
/// The alternative -- an early <c>return</c> inside the test body when the file is missing
/// -- reports the test as <b>passed</b>. That is the failure this project treats as the
/// expensive one: a run that shows green while the thing under test was never executed.
/// Setting <see cref="FactAttribute.Skip"/> makes the gap visible in the run output, and
/// the reason names the exact path that was looked for.
/// </para>
/// <para>
/// A constant <c>[Fact(Skip = "...")]</c> would not do either, because it skips on the
/// machine that does have the vector.
/// </para>
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class FixtureFactAttribute : FactAttribute
{
    /// <summary>Declares the vectors this test needs.</summary>
    /// <param name="requiredPaths">
    /// The required vectors, relative to <see cref="TestVectors.Root"/>. These are
    /// attribute arguments, so they are the compile-time constants on
    /// <see cref="TestVectors"/>; the machine-specific part of the path is resolved here,
    /// at run time.
    /// </param>
    public FixtureFactAttribute(params string[] requiredPaths)
    {
        Skip = TestVectors.SkipReasonFor(requiredPaths);
    }
}
