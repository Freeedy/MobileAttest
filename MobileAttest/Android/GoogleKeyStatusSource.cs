using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Math;

namespace MobileAttest.Android;

/// <summary>
/// Reads key status from a published attestation status list, fetched over HTTP.
/// </summary>
/// <remarks>
/// <para><b>The client and the address are both the caller's</b></para>
/// <para>
/// This type creates no <see cref="HttpClient"/> and carries no default address. The client's
/// lifetime governs socket exhaustion and DNS refresh, which are properties of the application
/// hosting it and not of a verification library; and there is no address in this assembly to
/// fall back to, so a deployment always states where it is looking. Both arrive through the
/// constructor.
/// </para>
/// <para><b>The document it expects</b></para>
/// <code>
/// {
///   "entries": {
///     "&lt;serial number, lower-case hexadecimal&gt;": { "status": "REVOKED" }
///   }
/// }
/// </code>
/// <para>
/// A serial number that is absent from <c>entries</c> is <see cref="KeyStatus.Valid"/>: the
/// document is a list of keys that are no longer good, so absence from a list that was fetched
/// and parsed is the list saying so. A document with no <c>entries</c> member is
/// <see cref="KeyStatus.Unknown"/> instead -- nothing can be read as absent from a list that
/// was never found.
/// </para>
/// <para><b>Every recoverable failure is an Unknown, not an exception</b></para>
/// <para>
/// An unreachable host, a refused connection, a request that timed out, an error status code, a
/// body that is not JSON, a document of the wrong shape and a status word this type does not
/// recognise all return <see cref="KeyStatus.Unknown"/>. A verifier must be able to turn a
/// status service being down into a policy decision; if this threw, every caller would be
/// forced to wrap it, and the one that forgot would answer requests with an unhandled
/// exception because a third party's web server was unwell.
/// </para>
/// <para>
/// Cancellation by the caller is the exception, and is propagated. A caller who abandons a
/// request wants it abandoned, and reporting <see cref="KeyStatus.Unknown"/> instead would let
/// verification carry on under <see cref="RevocationPolicy.Skip"/> after the caller asked for
/// it to stop.
/// </para>
/// <para><b>One request per lookup</b></para>
/// <para>
/// The whole list is fetched each time this is called. Wrap it in
/// <see cref="CachedKeyStatusSource"/>; unwrapped, it issues a request per verification.
/// </para>
/// </remarks>
public sealed class GoogleKeyStatusSource : IKeyStatusSource
{
    private const string EntriesPropertyName = "entries";
    private const string StatusPropertyName = "status";
    private const string RevokedStatus = "REVOKED";
    private const string SuspendedStatus = "SUSPENDED";

    private readonly HttpClient _httpClient;
    private readonly Uri _endpoint;

    /// <summary>Creates a source over a caller-supplied client and address.</summary>
    /// <param name="httpClient">
    /// The client requests are made on. Its lifetime, its handler, its timeout and its proxy
    /// settings are the caller's; nothing here configures it.
    /// </param>
    /// <param name="endpoint">
    /// The address of the status list. There is no default. A relative address is resolved
    /// against the client's <see cref="HttpClient.BaseAddress"/>, so one must be set if a
    /// relative address is used.
    /// </param>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    public GoogleKeyStatusSource(HttpClient httpClient, Uri endpoint)
    {
        if (httpClient is null)
        {
            throw new ArgumentNullException(nameof(httpClient));
        }

        if (endpoint is null)
        {
            // Refused at construction rather than turned into an Unknown on every lookup. A
            // missing address is a deployment mistake, and under Skip an Unknown would hide it
            // for as long as the deployment lasted.
            throw new ArgumentNullException(nameof(endpoint));
        }

        _httpClient = httpClient;
        _endpoint = endpoint;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException">
    /// <paramref name="serialNumber"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="OperationCanceledException">
    /// <paramref name="cancellationToken"/> was cancelled by the caller.
    /// </exception>
    public async Task<KeyStatus> GetStatusAsync(
        BigInteger serialNumber,
        CancellationToken cancellationToken = default)
    {
        if (serialNumber is null)
        {
            throw new ArgumentNullException(nameof(serialNumber));
        }

        try
        {
            using HttpResponseMessage response = await _httpClient
                .GetAsync(_endpoint, cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                // The body of an error response is whatever the server felt like sending --
                // an HTML error page, a proxy notice -- and is never a status list.
                return KeyStatus.Unknown;
            }

            string body = await response.Content
                .ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);

            return ReadStatus(body, serialNumber);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The caller asked to stop. Distinguished from the case below by the token, which
            // is the only thing that tells a caller's cancellation apart from the client's own
            // timeout -- both arrive here as the same exception type.
            throw;
        }
        catch (OperationCanceledException)
        {
            // The client's timeout elapsed.
            return KeyStatus.Unknown;
        }
        catch (HttpRequestException)
        {
            // Name resolution, connection, TLS, a truncated response.
            return KeyStatus.Unknown;
        }
        catch (JsonException)
        {
            // A body that is not JSON at all, or that stops in the middle.
            return KeyStatus.Unknown;
        }
        catch (InvalidOperationException)
        {
            // A request the client cannot make as configured -- a relative address with no
            // base address being the one a deployment actually hits.
            return KeyStatus.Unknown;
        }
    }

    /// <summary>Reads one serial number's status out of the fetched document.</summary>
    /// <remarks>
    /// A status word this type does not recognise yields <see cref="KeyStatus.Unknown"/> rather
    /// than a guess in either direction. Reading it as <see cref="KeyStatus.Valid"/> would
    /// accept a key that the list went out of its way to mention, and reading it as
    /// <see cref="KeyStatus.Revoked"/> would report a specific claim the document did not make.
    /// </remarks>
    private static KeyStatus ReadStatus(string body, BigInteger serialNumber)
    {
        using JsonDocument document = JsonDocument.Parse(body);

        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            return KeyStatus.Unknown;
        }

        if (!document.RootElement.TryGetProperty(EntriesPropertyName, out JsonElement entries) ||
            entries.ValueKind != JsonValueKind.Object)
        {
            return KeyStatus.Unknown;
        }

        if (!entries.TryGetProperty(FormatSerialNumber(serialNumber), out JsonElement entry))
        {
            // Fetched, parsed, and this key is not in it.
            return KeyStatus.Valid;
        }

        if (entry.ValueKind != JsonValueKind.Object ||
            !entry.TryGetProperty(StatusPropertyName, out JsonElement status) ||
            status.ValueKind != JsonValueKind.String)
        {
            return KeyStatus.Unknown;
        }

        return status.GetString() switch
        {
            RevokedStatus => KeyStatus.Revoked,
            SuspendedStatus => KeyStatus.Suspended,
            _ => KeyStatus.Unknown,
        };
    }

    /// <summary>
    /// Renders a serial number the way the document keys it: lower-case hexadecimal, with no
    /// leading zeroes and no separators.
    /// </summary>
    /// <remarks>
    /// JSON member lookup is ordinal, so the case is fixed here rather than left to whatever
    /// the underlying formatter happens to produce. A key written any other way simply will not
    /// match, which reports <see cref="KeyStatus.Valid"/> -- the reason this formatting is a
    /// named step with a test on it rather than an expression inline.
    /// </remarks>
    internal static string FormatSerialNumber(BigInteger serialNumber) =>
        serialNumber.ToString(16).ToLowerInvariant();
}
