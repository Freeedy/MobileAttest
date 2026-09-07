using System.Net;
using System.Net.Http;
using System.Text;
using MobileAttest.Abstractions;
using MobileAttest.Android;
using MobileAttest.Tests.TestSupport;
using Org.BouncyCastle.X509;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace MobileAttest.Tests.Android;

/// <summary>
/// Covers the key status step: the two policies, the cache, and the HTTP source.
/// </summary>
/// <remarks>
/// <para>
/// <b>Not one of these tests needs a device vector, and not one of them touches a network.</b>
/// The status source is a test double throughout, and the certificate chain is generated here.
/// A test that depended on a status service being reachable would fail for reasons that have
/// nothing to do with this code, and would look exactly like a defect in it.
/// </para>
/// <para>
/// <b>What is therefore not proven here:</b> that <see cref="GoogleKeyStatusSource"/> reads a
/// real published status list correctly. It is exercised against responses written in this
/// file. The shape of the live document was not measured, and nothing here claims it.
/// </para>
/// <para>
/// Every rejection test is paired with a control that accepts. Without one, a chain that was
/// broken for some unrelated reason would satisfy every "is refused" assertion in this file
/// while proving nothing about revocation at all.
/// </para>
/// </remarks>
public class KeyStatusTests
{
    private const string ExampleEndpoint = "https://status.example.test/attestation/status.json";

    // 1
    [Fact]
    public async Task AC4_SkipPolicyWithoutStatusSource_MakesNoHttpCall()
    {
        RecordingHandler handler = RecordingHandler.Returning(EmptyStatusList);
        using HttpClient client = new HttpClient(handler);

        AcceptedChain chain = AcceptedChain.Create(RevocationPolicy.Skip);

        // A verifier built the way a caller who wants no revocation lookup builds one: policy
        // chosen, no source supplied.
        AttestationResult result = await new AndroidKeyAttestationVerifier(chain.Options, chain.Clock)
            .VerifyAsync(chain.Request);

        Assert.True(result.IsValid, $"expected the attestation to verify, got {result.Reason}");
        Assert.Equal(0, handler.CallCount);

        // The control, and the reason the assertion above means anything. A counter that
        // cannot count would also report zero, so the same handler is shown recording a
        // request once a source is actually wired to it.
        AttestationResult wired = await new AndroidKeyAttestationVerifier(
                chain.Options,
                chain.Clock,
                new GoogleKeyStatusSource(client, new Uri(ExampleEndpoint)))
            .VerifyAsync(chain.Request);

        Assert.True(wired.IsValid, $"expected the attestation to verify, got {wired.Reason}");
        Assert.Equal(1, handler.CallCount);
    }

    // 2
    [Fact]
    public async Task AC5_RevokedKey_IsRejectedUnderEveryPolicy()
    {
        foreach (RevocationPolicy policy in AllPolicies)
        {
            AcceptedChain chain = AcceptedChain.Create(policy);

            // The control: the same chain, the same options, the same clock, and a source that
            // answers Valid. If this did not pass, the refusal below would prove nothing.
            AttestationResult accepted = await chain.Verify(new StubKeyStatusSource(KeyStatus.Valid));

            Assert.True(accepted.IsValid, $"under {policy} a valid key was refused: {accepted.Reason}");

            AttestationResult refused = await chain.Verify(new StubKeyStatusSource(KeyStatus.Revoked));

            // Revocation is not a policy question. The policy decides what silence costs; a
            // source that answers "revoked" is obeyed under either value.
            Assert.False(refused.IsValid, $"under {policy} a revoked key was accepted");
            Assert.Equal(AttestationFailureReason.CertificateRevoked, refused.Reason);
        }
    }

    // 3
    [Fact]
    public async Task AC6_SuspendedKey_IsRejected()
    {
        foreach (RevocationPolicy policy in AllPolicies)
        {
            AcceptedChain chain = AcceptedChain.Create(policy);

            AttestationResult accepted = await chain.Verify(new StubKeyStatusSource(KeyStatus.Valid));
            Assert.True(accepted.IsValid, $"under {policy} a valid key was refused: {accepted.Reason}");

            AttestationResult refused = await chain.Verify(new StubKeyStatusSource(KeyStatus.Suspended));

            // Suspended is not a lesser revoked. A key its issuer has withdrawn, however
            // temporarily, is not one to enrol a device on.
            Assert.False(refused.IsValid, $"under {policy} a suspended key was accepted");
            Assert.Equal(AttestationFailureReason.CertificateRevoked, refused.Reason);
        }
    }

    // 4
    [Fact]
    public async Task AC7_HardFail_UnknownStatus_IsRejected()
    {
        AcceptedChain chain = AcceptedChain.Create(RevocationPolicy.HardFail);

        AttestationResult accepted = await chain.Verify(new StubKeyStatusSource(KeyStatus.Valid));
        Assert.True(accepted.IsValid, $"a valid key was refused under HardFail: {accepted.Reason}");

        AttestationResult refused = await chain.Verify(new StubKeyStatusSource(KeyStatus.Unknown));

        Assert.False(refused.IsValid);

        // Not CertificateRevoked. Nobody said this key was revoked; the point is that nobody
        // said anything, and whoever reads the log has to be able to tell those apart.
        Assert.Equal(AttestationFailureReason.RevocationStatusUnavailable, refused.Reason);
    }

    // 5
    [Fact]
    public async Task AC8_Skip_UnknownStatus_ContinuesVerification()
    {
        AcceptedChain chain = AcceptedChain.Create(RevocationPolicy.Skip);

        AttestationResult result = await chain.Verify(new StubKeyStatusSource(KeyStatus.Unknown));

        // The offline case: a deployment with no status source, or one whose source is down,
        // keeps verifying. This is the caller's explicit choice, not a fallback.
        Assert.True(result.IsValid, $"Skip refused an unknown status: {result.Reason}");
        Assert.Equal(AttestationFailureReason.None, result.Reason);

        // Verification did not merely avoid failing -- it ran to the end and produced the
        // attested material. An early return would also have satisfied IsValid.
        Assert.False(result.KeyId.IsEmpty);
        Assert.False(result.PublicKeyDer.IsEmpty);
        Assert.Equal(Platform.Android, result.Platform);
    }

    // 6
    [Fact]
    public async Task AC9_StatusCache_SecondLookupUsesCache()
    {
        AcceptedChain chain = AcceptedChain.Create(RevocationPolicy.HardFail);

        StubKeyStatusSource inner = new StubKeyStatusSource(KeyStatus.Valid);
        CachedKeyStatusSource cache = new CachedKeyStatusSource(
            inner,
            chain.Options.StatusCacheTtl,
            chain.Clock);

        AttestationResult first = await chain.Verify(cache);
        AttestationResult second = await chain.Verify(cache);

        Assert.True(first.IsValid, $"first verification failed: {first.Reason}");
        Assert.True(second.IsValid, $"second verification failed: {second.Reason}");

        // One lookup for two verifications of the same key. Without this, every request a
        // device makes becomes a request to somebody else's web server.
        Assert.Equal(1, inner.CallCount);

        // A different serial is a different question and is asked. Otherwise a cache that
        // returned its first answer to everything would also pass the assertion above.
        await cache.GetStatusAsync(new BigInteger("5ee7", 16));
        Assert.Equal(2, inner.CallCount);
    }

    // 7
    [Fact]
    public async Task AC9_StatusCache_ExpiredEntry_IsRefetched()
    {
        AcceptedChain chain = AcceptedChain.Create(RevocationPolicy.HardFail);

        TimeSpan timeToLive = TimeSpan.FromHours(24);
        AdvanceableClock clock = new AdvanceableClock(chain.Clock.GetUtcNow());
        StubKeyStatusSource inner = new StubKeyStatusSource(KeyStatus.Valid);
        CachedKeyStatusSource cache = new CachedKeyStatusSource(inner, timeToLive, clock);

        BigInteger serial = chain.SerialNumber;

        Assert.Equal(KeyStatus.Valid, await cache.GetStatusAsync(serial));
        Assert.Equal(1, inner.CallCount);

        // One second short of expiry the held answer is still the answer.
        clock.Advance(timeToLive - TimeSpan.FromSeconds(1));
        Assert.Equal(KeyStatus.Valid, await cache.GetStatusAsync(serial));
        Assert.Equal(1, inner.CallCount);

        // Past it, the source is asked again. A cache with no expiry would hold a key's status
        // from the day it was first seen until the process was restarted, which is indefinite
        // for a server -- and the whole reason to look revocation up is that it changes.
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.Equal(KeyStatus.Valid, await cache.GetStatusAsync(serial));
        Assert.Equal(2, inner.CallCount);

        // And the refreshed answer is the new one, not the one that was held.
        inner.Status = KeyStatus.Revoked;
        clock.Advance(timeToLive);
        Assert.Equal(KeyStatus.Revoked, await cache.GetStatusAsync(serial));
        Assert.Equal(3, inner.CallCount);
    }

    // 8
    [Fact]
    public async Task AC10_StatusSource_NetworkFailure_YieldsUnknownNotException()
    {
        // Name resolution or connection failure: the endpoint is not there at all.
        await AssertYieldsUnknown(RecordingHandler.Throwing(
            () => new HttpRequestException("No such host is known.")));

        // The client's own timeout. It surfaces as a cancellation exception with no caller
        // token cancelled, which is the only thing distinguishing it from a caller who
        // abandoned the request -- and that distinction is the one this has to get right.
        await AssertYieldsUnknown(RecordingHandler.Throwing(
            () => new TaskCanceledException("The request timed out.", new TimeoutException())));
    }

    // 9
    [Fact]
    public async Task AC10_StatusSource_MalformedJson_YieldsUnknown()
    {
        // A body that is not JSON at all -- a proxy's HTML error page is the usual one.
        await AssertYieldsUnknown(RecordingHandler.Returning("<html>not json</html>"));

        // JSON that stops in the middle, which is what a truncated response looks like.
        await AssertYieldsUnknown(RecordingHandler.Returning("{\"entries\": {\"01\": "));

        // Well-formed JSON of the wrong shape. This is the one a naive parser accepts.
        await AssertYieldsUnknown(RecordingHandler.Returning("[1, 2, 3]"));

        // Well-formed, right root, no entries member: nothing can be read as absent from a
        // list that was never found, so this is Unknown and emphatically not Valid.
        await AssertYieldsUnknown(RecordingHandler.Returning("{\"something\": \"else\"}"));
    }

    // 10
    [Fact]
    public async Task AC10_StatusSource_HttpErrorStatus_YieldsUnknown()
    {
        foreach (HttpStatusCode code in new[]
                 {
                     HttpStatusCode.InternalServerError,
                     HttpStatusCode.NotFound,
                     HttpStatusCode.Forbidden,
                     HttpStatusCode.ServiceUnavailable,
                 })
        {
            // The body is a valid, empty status list. So an implementation that read the body
            // without looking at the status code would answer Valid here, and this is the
            // assertion that catches it.
            await AssertYieldsUnknown(RecordingHandler.Returning(EmptyStatusList, code));
        }
    }

    // 11
    [Fact]
    public async Task AC11_StatusSource_EndpointIsSuppliedNotHardcoded()
    {
        // The serial and the document key are written independently here: the key below is a
        // literal, not something produced by the code under test. A test that formatted the
        // key with the same helper the source uses would agree with it about any mistake.
        BigInteger serial = new BigInteger("1a2b3c4d", 16);
        const string listing = "{\"entries\": {\"1a2b3c4d\": {\"status\": \"REVOKED\"}}}";

        foreach (string address in new[]
                 {
                     ExampleEndpoint,
                     "https://another.example.test/some/other/path.json",
                 })
        {
            RecordingHandler handler = RecordingHandler.Returning(listing);
            using HttpClient client = new HttpClient(handler);

            KeyStatus status = await new GoogleKeyStatusSource(client, new Uri(address))
                .GetStatusAsync(serial);

            // The request went exactly where the caller said, and nowhere else. There is no
            // address in the library for it to have used instead.
            Assert.Equal(new Uri(address), Assert.Single(handler.Requests));
            Assert.Equal(KeyStatus.Revoked, status);
        }

        // A serial that is not in the fetched list is Valid: the document was retrieved and
        // parsed, and it does not name this key.
        RecordingHandler present = RecordingHandler.Returning(listing);
        using HttpClient other = new HttpClient(present);

        Assert.Equal(
            KeyStatus.Valid,
            await new GoogleKeyStatusSource(other, new Uri(ExampleEndpoint))
                .GetStatusAsync(new BigInteger("99", 16)));

        // And there is no address to fall back on, so none may be omitted.
        using HttpClient unused = new HttpClient(RecordingHandler.Returning(EmptyStatusList));
        Assert.Throws<ArgumentNullException>(() => new GoogleKeyStatusSource(unused, null!));
        Assert.Throws<ArgumentNullException>(() => new GoogleKeyStatusSource(null!, new Uri(ExampleEndpoint)));
    }

    // 12
    [Fact]
    public void AC18_Options_RevocationPolicyNotSelected_IsRejected()
    {
        // No default. The property reports "not selected" rather than a policy nobody chose.
        Assert.Null(new AndroidAttestOptions().RevocationPolicy);

        TestChain chain = TestChainBuilder.Create();

        // Complete in every other respect: a digest allowlist and a pinned root. So the only
        // thing left to reject it for is the policy, which is what makes the message assertion
        // below meaningful rather than incidental.
        AndroidAttestOptions missing = new AndroidAttestOptions
        {
            AllowedSignatureDigests = new[] { Convert.ToHexString(SyntheticDigest) },
            PinnedRootCertificates = chain.PinnedRoots,
        };

        InvalidOperationException error =
            Assert.Throws<InvalidOperationException>(() => missing.Validate());

        Assert.Contains(
            nameof(AndroidAttestOptions.RevocationPolicy),
            error.Message,
            StringComparison.Ordinal);

        // Either choice is a complete configuration. Neither is preferred, and neither is
        // reached by leaving the field alone.
        foreach (RevocationPolicy policy in AllPolicies)
        {
            AndroidAttestOptions selected = new AndroidAttestOptions
            {
                AllowedSignatureDigests = missing.AllowedSignatureDigests,
                PinnedRootCertificates = missing.PinnedRootCertificates,
                RevocationPolicy = policy,
            };

            selected.Validate();
        }

        // The default time-to-live is a value, not an accident: an unset one would mean every
        // verification asks the source again.
        Assert.Equal(TimeSpan.FromHours(24), new AndroidAttestOptions().StatusCacheTtl);
    }

    // 13
    [Fact]
    public async Task AC19_HardFailWithoutStatusSource_RejectsEveryVerification()
    {
        AcceptedChain chain = AcceptedChain.Create(RevocationPolicy.HardFail);

        // HardFail chosen, no source supplied. The empty source answers Unknown to everything,
        // so this configuration can never accept anything -- and it says so on the first
        // request rather than passing quietly.
        AndroidKeyAttestationVerifier verifier =
            new AndroidKeyAttestationVerifier(chain.Options, chain.Clock);

        for (int attempt = 0; attempt < 3; attempt++)
        {
            AttestationResult result = await verifier.VerifyAsync(chain.Request);

            // "Every verification", not "the first one": a source that answered once and then
            // gave up, or a cache that held a pass, would show up as attempt two or three.
            Assert.False(result.IsValid, $"attempt {attempt} was accepted with no status source");
            Assert.Equal(AttestationFailureReason.RevocationStatusUnavailable, result.Reason);
        }

        // The control. The same chain, options and clock are accepted the moment a source can
        // actually answer, so the refusals above are caused by the missing source and not by
        // something else wrong with the chain.
        AttestationResult withSource = await chain.Verify(new StubKeyStatusSource(KeyStatus.Valid));

        Assert.True(withSource.IsValid, $"the chain itself does not verify: {withSource.Reason}");
    }

    private static IEnumerable<RevocationPolicy> AllPolicies =>
        new[] { RevocationPolicy.Skip, RevocationPolicy.HardFail };

    /// <summary>A well-formed status list naming no key at all.</summary>
    private const string EmptyStatusList = "{\"entries\": {}}";

    /// <summary>A 32-byte digest that belongs to no real application.</summary>
    private static byte[] SyntheticDigest =>
        Enumerable.Range(0, 32).Select(i => (byte)(0x80 + i)).ToArray();

    /// <summary>
    /// Asserts that a source over this handler answers <see cref="KeyStatus.Unknown"/> and
    /// lets nothing escape to the caller.
    /// </summary>
    private static async Task AssertYieldsUnknown(RecordingHandler handler)
    {
        using HttpClient client = new HttpClient(handler);

        GoogleKeyStatusSource source = new GoogleKeyStatusSource(client, new Uri(ExampleEndpoint));

        KeyStatus status = KeyStatus.Valid;
        Exception? thrown = await Record.ExceptionAsync(async () =>
            status = await source.GetStatusAsync(new BigInteger("2a", 16)));

        // A status service that is down must become a policy decision, never an unhandled
        // exception in the caller's request path.
        Assert.True(thrown is null, $"the source threw {thrown?.GetType().Name}: {thrown?.Message}");
        Assert.Equal(KeyStatus.Unknown, status);
    }

    /// <summary>
    /// A generated chain the verifier accepts, so that a test can change the key status and
    /// nothing else.
    /// </summary>
    /// <remarks>
    /// Everything here is synthetic. The record carries the field arrangement measured on a
    /// real device, and none of its values: no vector is needed to reach the status step, which
    /// is why every test in this file runs on a clean clone.
    /// </remarks>
    private sealed class AcceptedChain
    {
        private readonly TestChain _chain;

        private AcceptedChain(TestChain chain, AndroidAttestOptions options, byte[] challenge)
        {
            _chain = chain;
            Options = options;
            Request = new AndroidAttestationRequest(
                chain.Der.Select(der => (ReadOnlyMemory<byte>)der).ToArray(),
                challenge);
        }

        public AndroidAttestOptions Options { get; }

        public AndroidAttestationRequest Request { get; }

        /// <summary>An instant inside the window the generated hierarchy is valid over.</summary>
        public TimeProvider Clock { get; } = FixedTimeProvider.AtUtc(2026, 6, 1);

        /// <summary>The serial number the status source will be asked about.</summary>
        public BigInteger SerialNumber => _chain.Leaf.SerialNumber;

        public static AcceptedChain Create(RevocationPolicy policy)
        {
            byte[] digest = Enumerable.Range(0, 32).Select(i => (byte)(0x10 + i)).ToArray();
            byte[] challenge = Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();

            KeyDescriptionBuilder record = KeyDescriptionBuilder.RealisticLayout();
            record.AttestationChallenge = challenge;
            record.SoftwareEnforced.AttestationApplicationId =
                KeyDescriptionBuilder.EncodeAttestationApplicationId(
                    new[] { ("com.example.status", 1L) },
                    new[] { digest });

            TestChain chain = TestChainBuilder.Create(leafKeyAttestationRecord: record.Build());

            AndroidAttestOptions options = new AndroidAttestOptions
            {
                AllowedSignatureDigests = new[] { Convert.ToHexString(digest) },
                PinnedRootCertificates = chain.PinnedRoots,
                RevocationPolicy = policy,
            };

            return new AcceptedChain(chain, options, challenge);
        }

        /// <summary>Verifies this chain against a status source.</summary>
        public Task<AttestationResult> Verify(IKeyStatusSource statusSource) =>
            new AndroidKeyAttestationVerifier(Options, Clock, statusSource).VerifyAsync(Request);
    }

    /// <summary>A status source that answers with a fixed value and counts the asking.</summary>
    private sealed class StubKeyStatusSource : IKeyStatusSource
    {
        public StubKeyStatusSource(KeyStatus status) => Status = status;

        /// <summary>The answer given. Settable, so a test can change it behind a cache.</summary>
        public KeyStatus Status { get; set; }

        /// <summary>How many times the source was consulted.</summary>
        public int CallCount { get; private set; }

        public Task<KeyStatus> GetStatusAsync(
            BigInteger serialNumber,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(Status);
        }
    }

    /// <summary>
    /// A handler that records what was asked of it and answers from a script, so that "no HTTP
    /// call was made" is something a test can assert rather than assume.
    /// </summary>
    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpResponseMessage> _respond;

        private RecordingHandler(Func<HttpResponseMessage> respond) => _respond = respond;

        /// <summary>Every address requested, in order.</summary>
        public List<Uri?> Requests { get; } = new List<Uri?>();

        /// <summary>How many requests reached this handler.</summary>
        public int CallCount => Requests.Count;

        public static RecordingHandler Returning(string body, HttpStatusCode code = HttpStatusCode.OK) =>
            new RecordingHandler(() => new HttpResponseMessage(code)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });

        public static RecordingHandler Throwing(Func<Exception> failure) =>
            new RecordingHandler(() => throw failure());

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri);
            return Task.FromResult(_respond());
        }
    }

    /// <summary>A clock a test can move, for expiry that would otherwise need waiting.</summary>
    private sealed class AdvanceableClock : TimeProvider
    {
        private DateTimeOffset _now;

        public AdvanceableClock(DateTimeOffset now) => _now = now;

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
