using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Kennwort.Tests;

internal sealed class FakeBreaches(long count = 0, Exception? fail = null) : IBreachedPasswordChecker
{
    public List<string> Asked { get; } = [];

    public Task<long> CountAsync(string password, CancellationToken ct = default)
    {
        Asked.Add(password);
        return fail is null ? Task.FromResult(count) : Task.FromException<long>(fail);
    }
}

internal sealed class FakeHandler(Func<HttpRequestMessage, (HttpStatusCode, string)> respond) : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        var (status, body) = respond(request);
        return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body) });
    }
}

public class PwnedPasswordsTests
{
    [Fact]
    public void SplitsSha1IntoPrefixAndSuffix()
    {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        var (prefix, suffix) = PwnedPasswordsClient.Split("password");
        Assert.Equal("5BAA6", prefix);
        Assert.Equal("1E4C9B93F3F0682250B6CF8331B7EE68FD8", suffix);
    }

    [Fact]
    public async Task SendsOnlyThePrefixWithPadding()
    {
        var handler = new FakeHandler(_ => (HttpStatusCode.OK,
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:52372427\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\r\n"));
        var client = new PwnedPasswordsClient(new HttpClient(handler), "https://hibp.test");
        Assert.Equal(52372427, await client.CountAsync("password"));

        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://hibp.test/range/5BAA6", request.RequestUri!.ToString());
        Assert.Equal("true", request.Headers.GetValues("Add-Padding").Single());
        Assert.DoesNotContain("1E4C9B", request.RequestUri.ToString()); // the suffix never leaves the machine
    }

    [Theory]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:7", 7)]
    [InlineData("1e4c9b93f3f0682250b6cf8331b7ee68fd8:7", 7)]   // case-insensitive
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0", 0)]   // a padding row
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD9:7", 0)]
    [InlineData("garbage", 0)]
    public void FindsTheSuffix(string body, long expected) =>
        Assert.Equal(expected, PwnedPasswordsClient.Find(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"));

    [Fact]
    public async Task ServerErrorThrows()
    {
        var client = new PwnedPasswordsClient(new HttpClient(new FakeHandler(_ => (HttpStatusCode.ServiceUnavailable, ""))));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.CountAsync("x"));
    }
}

public class PolicyTests
{
    private static List<string> Codes(string password, PasswordContext? c = null, PasswordPolicy? p = null) =>
        new PasswordChecker(p).CheckLocal(password, c ?? new PasswordContext()).Select(x => x.Code).ToList();

    [Theory]
    [InlineData("Blaues Fahrrad unter Linden")]
    [InlineData("kaffee-mond-ziegel-77")]
    [InlineData("Ünïcödé Wörter sind ok")]
    [InlineData("zwölf zeichen")]
    public void GoodPasswordsPass(string password) => Assert.Empty(Codes(password));

    [Fact]
    public void NoCompositionRules() => Assert.Empty(Codes("nur kleinbuchstaben ohne ziffern"));

    [Theory]
    [InlineData("Kurz1!")]
    [InlineData("elf zeichen")]
    public void TooShort(string password) => Assert.Equal(["too-short"], Codes(password));

    [Fact]
    public void LengthCountsCharactersNotBytes()
    {
        // 12 characters, but 24+ bytes in UTF-8, and a decomposed umlaut counts as one character after normalization
        Assert.DoesNotContain("too-short", Codes("grüße köln!!"));
        Assert.Equal(["too-short"], Codes("äääää", p: new PasswordPolicy { MinLength = 6 }));
    }

    [Fact]
    public void TooLong() => Assert.Equal(["too-long"], Codes(new string('x', 20) + string.Concat(Enumerable.Range(0, 120).Select(i => (char)('a' + i % 26)))));

    [Theory]
    [InlineData("passwordpassword")]
    [InlineData("P@ssw0rdP@ssw0rd")]   // de-leeted
    [InlineData("Passwort2024!!")]     // letters only: passwort
    [InlineData("Lieblingsmensch1")]
    [InlineData("P@ssw0rd2024!")]      // appended year, then de-leeted
    public void Common(string password) => Assert.Contains("common", Codes(password));

    [Theory]
    [InlineData("Sommer2024!!!")]
    [InlineData("winter2026!!!!")]
    [InlineData("Dezember24!!!!")]
    [InlineData("September2025")]
    public void SeasonOrMonthWithYear(string password) => Assert.Contains("season-year", Codes(password));

    [Fact]
    public void SeasonWordsInsideALongerPhraseAreFine() => Assert.Empty(Codes("im Sommer am See lesen"));

    [Theory]
    [InlineData("amarkaric1990x", "amar.karic", null, "karic")]
    [InlineData("4m4r-und-der-hund", "amar", null, "amar")]          // leetspeak
    [InlineData("musterfirma-zugang", null, "a.b@musterfirma.de", "musterfirma")]
    public void ContextWords(string password, string? user, string? email, string word)
    {
        var problems = new PasswordChecker().CheckLocal(password, new PasswordContext(user, email)).ToList();
        var p = Assert.Single(problems, x => x.Code == "context");
        Assert.Contains($"\"{word}\"", p.English);
    }

    [Fact]
    public void ServiceWordsFromPolicy() =>
        Assert.Contains("context", Codes("kontor-zugang-hamburg", p: new PasswordPolicy { ContextWords = ["Kontor"] }));

    [Fact]
    public void ShortContextPartsAreIgnored() => Assert.Empty(Codes("ab und zu ein see", new PasswordContext("ab")));

    [Theory]
    [InlineData("aaaaaaaaaaaa", "repetition")]
    [InlineData("gutes passwort xxxx", "repetition")]
    [InlineData("abcabcabcabc", "pattern")]
    [InlineData("hahahahahaha", "pattern")]
    [InlineData("qwertz-lampe-blau", "sequence")]
    [InlineData("blume 12345 garten", "sequence")]
    [InlineData("zyxwv und noch was", "sequence")]   // descending
    [InlineData("asdfgh im regen", "sequence")]
    public void PatternsAndSequences(string password, string code) => Assert.Contains(code, Codes(password));

    [Theory]
    [InlineData("abcd", 4)]
    [InlineData("a1b2c3", 1)]
    [InlineData("xx98765xx", 5)]
    [InlineData("qwertzu", 7)]
    public void LongestSequence(string s, int expected) => Assert.Equal(expected, PasswordChecker.LongestSequence(s));

    [Theory]
    [InlineData("p@ssw0rd", "password")]
    [InlineData("$0mm3r", "sommer")]
    public void Deleet(string input, string expected) => Assert.Equal(expected, PasswordChecker.Deleet(input));

    [Fact]
    public void EveryProblemHasGermanText()
    {
        var all = new[] { "kurz", "passwordpassword", "Sommer2024!!!", "aaaaaaaaaaaa", "abcabcabcabc", "qwertz-lampe-blau" }
            .SelectMany(p => new PasswordChecker().CheckLocal(p, new PasswordContext())).ToList();
        Assert.All(all, p => Assert.False(string.IsNullOrWhiteSpace(p.German)));
        Assert.Contains(all, p => p.German.Contains("Jahreszeit"));
    }
}

public class CheckerTests
{
    [Fact]
    public async Task BreachedPasswordIsRejected()
    {
        var r = await new PasswordChecker(null, new FakeBreaches(391)).CheckAsync("correct horse battery staple");
        Assert.False(r.Accepted);
        Assert.Equal("breached", Assert.Single(r.Problems).Code);
        Assert.Contains("391 time(s)", r.Problems[0].English);
        Assert.Equal(391, r.BreachCount);
    }

    [Fact]
    public async Task ThresholdIsPolicy()
    {
        var r = await new PasswordChecker(new PasswordPolicy { BreachThreshold = 1000 }, new FakeBreaches(391)).CheckAsync("correct horse battery staple");
        Assert.True(r.Accepted);
    }

    [Fact]
    public async Task LocallyRejectedPasswordsAreNotSentToHibp()
    {
        var hibp = new FakeBreaches();
        await new PasswordChecker(null, hibp).CheckAsync("kurz");
        await new PasswordChecker(null, hibp).CheckAsync("aaaaaaaaaaaaaaa");
        Assert.Empty(hibp.Asked);
    }

    [Theory]
    [InlineData(BreachCheckFailure.Allow, true)]
    [InlineData(BreachCheckFailure.Reject, false)]
    public async Task OutageBehaviourIsPolicy(BreachCheckFailure mode, bool accepted)
    {
        var r = await new PasswordChecker(new PasswordPolicy { OnBreachCheckFailure = mode }, new FakeBreaches(fail: new HttpRequestException("down")))
            .CheckAsync("Blaues Fahrrad unter Linden");
        Assert.Equal(accepted, r.Accepted);
        Assert.Contains("unavailable", Assert.Single(r.Notes));
    }

    [Fact]
    public async Task BreachCheckCanBeTurnedOff()
    {
        var hibp = new FakeBreaches(5);
        var r = await new PasswordChecker(new PasswordPolicy { CheckBreaches = false }, hibp).CheckAsync("Blaues Fahrrad unter Linden");
        Assert.True(r.Accepted);
        Assert.Empty(hibp.Asked);
    }
}

public class IdentityTests
{
    public sealed class User
    {
        public string Name { get; set; } = "";
        public string? Email { get; set; }
    }

    private sealed class Store : IUserEmailStore<User>
    {
        public Task<string?> GetUserNameAsync(User user, CancellationToken ct) => Task.FromResult<string?>(user.Name);
        public Task<string?> GetEmailAsync(User user, CancellationToken ct) => Task.FromResult(user.Email);
        public Task<string> GetUserIdAsync(User user, CancellationToken ct) => Task.FromResult(user.Name);
        public void Dispose() { }
        public Task SetUserNameAsync(User user, string? userName, CancellationToken ct) => Task.CompletedTask;
        public Task<string?> GetNormalizedUserNameAsync(User user, CancellationToken ct) => Task.FromResult<string?>(user.Name.ToUpperInvariant());
        public Task SetNormalizedUserNameAsync(User user, string? normalizedName, CancellationToken ct) => Task.CompletedTask;
        public Task<IdentityResult> CreateAsync(User user, CancellationToken ct) => Task.FromResult(IdentityResult.Success);
        public Task<IdentityResult> UpdateAsync(User user, CancellationToken ct) => Task.FromResult(IdentityResult.Success);
        public Task<IdentityResult> DeleteAsync(User user, CancellationToken ct) => Task.FromResult(IdentityResult.Success);
        public Task<User?> FindByIdAsync(string userId, CancellationToken ct) => Task.FromResult<User?>(null);
        public Task<User?> FindByNameAsync(string normalizedUserName, CancellationToken ct) => Task.FromResult<User?>(null);
        public Task SetEmailAsync(User user, string? email, CancellationToken ct) => Task.CompletedTask;
        public Task<bool> GetEmailConfirmedAsync(User user, CancellationToken ct) => Task.FromResult(true);
        public Task SetEmailConfirmedAsync(User user, bool confirmed, CancellationToken ct) => Task.CompletedTask;
        public Task<User?> FindByEmailAsync(string normalizedEmail, CancellationToken ct) => Task.FromResult<User?>(null);
        public Task<string?> GetNormalizedEmailAsync(User user, CancellationToken ct) => Task.FromResult(user.Email?.ToUpperInvariant());
        public Task SetNormalizedEmailAsync(User user, string? normalizedEmail, CancellationToken ct) => Task.CompletedTask;
    }

    private static (UserManager<User> Manager, ServiceProvider Services) Build(long breachCount = 0)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IUserStore<User>, Store>();
        var builder = services.AddIdentityCore<User>();
        builder.AddKennwort(new PasswordPolicy(), new HttpClient(new FakeHandler(r =>
        {
            // Answer like HIBP: the suffix of the asked password with the given count
            var hash = Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(System.Text.Encoding.UTF8.GetBytes(LastPassword!)));
            return (HttpStatusCode.OK, $"{hash[5..]}:{breachCount}\r\n");
        })));
        var sp = services.BuildServiceProvider();
        return (sp.GetRequiredService<UserManager<User>>(), sp);
    }

    private static string? LastPassword;

    private static async Task<IdentityResult> Validate(UserManager<User> manager, User user, string password)
    {
        LastPassword = password;
        var results = new List<IdentityResult>();
        foreach (var v in manager.PasswordValidators)
            results.Add(await v.ValidateAsync(manager, user, password));
        return results.FirstOrDefault(r => !r.Succeeded) ?? IdentityResult.Success;
    }

    [Fact]
    public async Task AcceptsLongPassphraseWithoutDigitsOrSymbols()
    {
        var (manager, sp) = Build();
        using var _ = sp;
        Assert.True((await Validate(manager, new User { Name = "amar" }, "blaues fahrrad unter linden")).Succeeded);
    }

    [Fact]
    public async Task UsesUserNameAndEmailAsContext()
    {
        var (manager, sp) = Build();
        using var _ = sp;
        var result = await Validate(manager, new User { Name = "erika", Email = "erika@musterbank.de" }, "musterbank-zugang-2026");
        Assert.False(result.Succeeded);
        Assert.Equal("Kennwort.context", Assert.Single(result.Errors).Code);
    }

    [Fact]
    public async Task RejectsBreachedPassword()
    {
        var (manager, sp) = Build(breachCount: 42);
        using var _ = sp;
        var result = await Validate(manager, new User { Name = "amar" }, "blaues fahrrad unter linden");
        Assert.Equal("Kennwort.breached", Assert.Single(result.Errors).Code);
    }

    [Fact]
    public void TurnsOffIdentityCompositionRules()
    {
        var (_, sp) = Build();
        using var _2 = sp;
        var o = sp.GetRequiredService<IOptions<IdentityOptions>>().Value.Password;
        Assert.False(o.RequireDigit || o.RequireUppercase || o.RequireLowercase || o.RequireNonAlphanumeric);
    }
}
