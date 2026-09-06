namespace MobileAttest.Tests.TestSupport;

/// <summary>
/// A theory that needs a real device vector, skipping with the same visible reason as
/// <see cref="FixtureFactAttribute"/> when the vector is absent.
/// </summary>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class FixtureTheoryAttribute : TheoryAttribute
{
    /// <summary>Declares the vectors this theory needs.</summary>
    /// <param name="requiredPaths">
    /// The required vectors, relative to <see cref="TestVectors.Root"/>.
    /// </param>
    public FixtureTheoryAttribute(params string[] requiredPaths)
    {
        Skip = TestVectors.SkipReasonFor(requiredPaths);
    }
}
