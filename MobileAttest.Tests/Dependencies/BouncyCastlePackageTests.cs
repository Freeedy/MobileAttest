using System.Reflection;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace MobileAttest.Tests.Dependencies;

/// <summary>
/// Guards the single runtime dependency. The types below were originally measured in a
/// local source checkout of bc-csharp, not in the published NuGet package, so their
/// presence in <c>BouncyCastle.Cryptography 2.7.0</c> is asserted here rather than assumed.
/// </summary>
public class BouncyCastlePackageTests
{
    [Fact]
    public void AC9_BouncyCastlePackage_ExposesRequiredTypes()
    {
        // The three type references below are compile-time proof: this file does not
        // build unless the referenced package actually carries them.
        Assert.NotNull(typeof(SecureRandom));
        Assert.NotNull(typeof(PkixCertPathValidator));
        Assert.NotNull(typeof(Arrays));

        // The constant-time comparison is a method, not a type, so it is checked by
        // signature: a rename or a changed parameter list must fail this test. It is
        // looked up by name rather than called, because the package marks it obsolete.
        MethodInfo? constantTimeAreEqual = typeof(Arrays).GetMethod(
            "ConstantTimeAreEqual",
            BindingFlags.Public | BindingFlags.Static,
            binder: null,
            types: new[] { typeof(byte[]), typeof(byte[]) },
            modifiers: null);
        Assert.NotNull(constantTimeAreEqual);
        Assert.Equal(typeof(bool), constantTimeAreEqual!.ReturnType);

        // Measured, not assumed: in package 2.7.0 that method is obsolete and the live
        // name is FixedTimeEquals. The passport recorded only the old name, from a source
        // checkout. Both facts are pinned here so a future package bump that drops either
        // one fails this test instead of silently changing what the library calls.
        Assert.NotEmpty(constantTimeAreEqual.GetCustomAttributes<ObsoleteAttribute>(inherit: false));

        MethodInfo? fixedTimeEquals = typeof(Arrays).GetMethod(
            nameof(Arrays.FixedTimeEquals),
            BindingFlags.Public | BindingFlags.Static,
            binder: null,
            types: new[] { typeof(byte[]), typeof(byte[]) },
            modifiers: null);
        Assert.NotNull(fixedTimeEquals);
        Assert.Empty(fixedTimeEquals!.GetCustomAttributes<ObsoleteAttribute>(inherit: false));

        // Supply-chain guard: the fork Portable.BouncyCastle ships an assembly named
        // "BouncyCastle.Crypto". Only the official package satisfies this assertion.
        AssemblyName dependency = typeof(SecureRandom).Assembly.GetName();
        Assert.Equal("BouncyCastle.Cryptography", dependency.Name);
        Assert.Equal(2, dependency.Version!.Major);
    }

    [Fact]
    public void AC9_SecureRandom_ProducesDifferentBytes()
    {
        SecureRandom random = new SecureRandom();

        byte[] first = new byte[32];
        byte[] second = new byte[32];
        random.NextBytes(first);
        random.NextBytes(second);

        // A CSPRNG returning the same 32 bytes twice is a 2^-256 event; in practice it
        // means the generator was never seeded or never ran.
        Assert.NotEqual(first, second);
        Assert.Contains(first, b => b != 0);
        Assert.Contains(second, b => b != 0);
    }
}
