using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Kennwort;

/// <summary>Is a password in a known breach corpus? Returns how often it was seen, 0 if never.</summary>
public interface IBreachedPasswordChecker
{
    Task<long> CountAsync(string password, CancellationToken ct = default);
}

/// <summary>
/// Have I Been Pwned "Pwned Passwords" with k-anonymity: only the first 5 hex characters of the SHA-1 hash are sent;
/// the API returns all ~1,000 suffixes with that prefix and the match happens locally. Neither the password nor its full hash
/// leaves the machine. With <c>Add-Padding</c> the response size does not reveal the prefix either (padding rows have count 0).
/// </summary>
public sealed class PwnedPasswordsClient : IBreachedPasswordChecker
{
    public const string DefaultBaseAddress = "https://api.pwnedpasswords.com/";

    private readonly HttpClient http;
    private readonly string baseAddress;

    public PwnedPasswordsClient(HttpClient http, string baseAddress = DefaultBaseAddress)
    {
        this.http = http;
        this.baseAddress = baseAddress.EndsWith('/') ? baseAddress : baseAddress + "/";
    }

    public async Task<long> CountAsync(string password, CancellationToken ct = default)
    {
        var (prefix, suffix) = Split(password);
        using var request = new HttpRequestMessage(HttpMethod.Get, $"{baseAddress}range/{prefix}");
        request.Headers.Add("Add-Padding", "true");
        using var response = await http.SendAsync(request, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return Find(await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false), suffix);
    }

    /// <summary>SHA-1 (upper-case hex) split into the 5-character prefix that is sent and the 35-character suffix that is not.</summary>
    internal static (string Prefix, string Suffix) Split(string password)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        return (hash[..5], hash[5..]);
    }

    /// <summary>Lines are "SUFFIX:COUNT". Padding lines have count 0 and never match a real password.</summary>
    internal static long Find(string body, string suffix)
    {
        foreach (var raw in body.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var colon = line.IndexOf(':');
            if (colon != 35) continue;
            if (!line.AsSpan(0, 35).Equals(suffix, StringComparison.OrdinalIgnoreCase)) continue;
            return long.TryParse(line.AsSpan(36), NumberStyles.Integer, CultureInfo.InvariantCulture, out var count) ? count : 0;
        }
        return 0;
    }
}
