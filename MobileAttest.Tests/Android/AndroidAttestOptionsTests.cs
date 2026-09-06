using MobileAttest.Android;

namespace MobileAttest.Tests.Android;

/// <summary>
/// Pins the Android policy defaults, so that a change of security posture has to be a
/// deliberate edit with a failing test attached.
/// </summary>
public class AndroidAttestOptionsTests
{
    [Fact]
    public void AC7_AndroidAttestOptions_RequireStrongBox_DefaultsToFalse()
    {
        AndroidAttestOptions options = new AndroidAttestOptions();

        // StrongBox is absent on many devices, so requiring it by default would silently
        // exclude hardware the caller may well intend to support. The default is recorded
        // here rather than left to be inferred from the field declaration.
        Assert.False(options.RequireStrongBox);
    }
}
