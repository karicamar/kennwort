using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Kennwort;

public enum BreachCheckFailure
{
    /// <summary>If HIBP is unreachable, accept the password (and report it). Sign-ups keep working during an outage.</summary>
    Allow,

    /// <summary>If HIBP is unreachable, reject the password. For high-security systems.</summary>
    Reject,
}

/// <summary>
/// The policy, following NIST SP 800-63B (rev. 4) and the BSI IT-Grundschutz (ORP.4): long passwords, no composition rules
/// ("one upper-case letter, one digit, one symbol"), no forced rotation, but a check against breached, common and
/// context-specific passwords.
/// </summary>
public sealed record PasswordPolicy
{
    /// <summary>NIST: at least 15 without MFA, at least 8 with MFA. 12 is a common middle ground; set it to fit your system.</summary>
    public int MinLength { get; init; } = 12;

    /// <summary>NIST: allow at least 64. Long limits only guard against denial of service through huge inputs to the hash.</summary>
    public int MaxLength { get; init; } = 128;

    /// <summary>Reject passwords seen in breaches at least this often (1 = any breach).</summary>
    public long BreachThreshold { get; init; } = 1;

    public bool CheckBreaches { get; init; } = true;
    public BreachCheckFailure OnBreachCheckFailure { get; init; } = BreachCheckFailure.Allow;

    /// <summary>Words of this service that must not be the basis of a password: company, product, domain.</summary>
    public IReadOnlyList<string> ContextWords { get; init; } = [];
}

public sealed record Problem(string Code, string English, string German);

public sealed record CheckResult(IReadOnlyList<Problem> Problems, long? BreachCount, IReadOnlyList<string> Notes)
{
    public bool Accepted => Problems.Count == 0;
}

/// <summary>Who the password is for, so it can be checked against their own name and email.</summary>
public sealed record PasswordContext(string? UserName = null, string? Email = null, IReadOnlyList<string>? Words = null);

public sealed partial class PasswordChecker
{
    private readonly PasswordPolicy policy;
    private readonly IBreachedPasswordChecker? breaches;

    public PasswordChecker(PasswordPolicy? policy = null, IBreachedPasswordChecker? breaches = null)
    {
        this.policy = policy ?? new PasswordPolicy();
        this.breaches = breaches;
    }

    public async Task<CheckResult> CheckAsync(string password, PasswordContext? context = null, CancellationToken ct = default)
    {
        var problems = CheckLocal(password, context ?? new PasswordContext()).ToList();
        var notes = new List<string>();
        long? count = null;

        // Only ask HIBP about passwords that pass the local rules: fewer requests, and short ones never leave the process
        if (problems.Count == 0 && policy.CheckBreaches && breaches is not null)
        {
            try
            {
                count = await breaches.CountAsync(password, ct).ConfigureAwait(false);
                if (count >= policy.BreachThreshold)
                    problems.Add(new Problem("breached",
                        string.Create(CultureInfo.InvariantCulture, $"This password appeared {count:N0} time(s) in data breaches. Attackers try these first."),
                        string.Create(CultureInfo.GetCultureInfo("de-DE"), $"Dieses Passwort ist {count:N0}-mal in Datenlecks aufgetaucht. Angreifer probieren solche Passwörter zuerst.")));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                notes.Add($"breach check unavailable ({ex.GetType().Name})");
                if (policy.OnBreachCheckFailure == BreachCheckFailure.Reject)
                    problems.Add(new Problem("breach-check-unavailable",
                        "The password could not be checked against known breaches. Please try again later.",
                        "Das Passwort konnte nicht gegen bekannte Datenlecks geprüft werden. Bitte später erneut versuchen."));
            }
        }
        return new CheckResult(problems, count, notes);
    }

    /// <summary>All rules that need no network. Deterministic and fast.</summary>
    public IEnumerable<Problem> CheckLocal(string password, PasswordContext context)
    {
        // NIST: normalize Unicode so "ﬁ" and "fi" or composed and decomposed umlauts count the same
        var normalized = password.Normalize(NormalizationForm.FormKC);
        var length = new StringInfo(normalized).LengthInTextElements;
        if (length < policy.MinLength)
        {
            yield return new Problem("too-short",
                $"Use at least {policy.MinLength} characters. A few unrelated words are easy to remember and hard to guess.",
                $"Bitte mindestens {policy.MinLength} Zeichen verwenden. Ein paar zusammenhanglose Wörter sind leicht zu merken und schwer zu erraten.");
            yield break; // the other rules are noise for a password that is too short anyway
        }
        if (length > policy.MaxLength)
        {
            yield return new Problem("too-long", $"Use at most {policy.MaxLength} characters.", $"Bitte höchstens {policy.MaxLength} Zeichen verwenden.");
            yield break;
        }

        // Three views of the password: as typed (patterns, sequences), its letters ("Passwort2024!" → passwort)
        // and de-leeted ("P@ssw0rd" → password) for comparing with words
        var lower = normalized.ToLowerInvariant();
        var plain = Deleet(lower);
        var core = Letters().Replace(lower, "");

        // "P@ssw0rd2024!": drop the appended digits and symbols first, then de-leet the rest
        var stem = Deleet(TrailingDigitsAndSymbols().Replace(lower, ""));
        if (CommonPasswords.Contains(core) || CommonPasswords.Contains(plain) || CommonPasswords.Contains(stem))
            yield return new Problem("common", "This is one of the most common passwords.", "Das ist eines der häufigsten Passwörter.");
        else if (SeasonOrMonthWithYear().IsMatch(lower))
            yield return new Problem("season-year",
                "A season or month with a year (\"Sommer2024!\") is one of the first patterns attackers try.",
                "Jahreszeit oder Monat mit Jahreszahl (\"Sommer2024!\") gehört zu den ersten Mustern, die Angreifer ausprobieren.");

        foreach (var word in ContextWords(context))
        {
            if (plain.Contains(word, StringComparison.Ordinal) || lower.Contains(word, StringComparison.Ordinal))
            {
                yield return new Problem("context",
                    $"Do not build the password from your name, email or this service (\"{word}\").",
                    $"Das Passwort darf nicht auf Ihrem Namen, Ihrer E-Mail-Adresse oder diesem Dienst aufbauen (\"{word}\").");
                break;
            }
        }

        if (RepeatedCharacter().IsMatch(normalized))
            yield return new Problem("repetition", "Avoid repeating the same character (\"aaaa\").", "Bitte keine Wiederholungen desselben Zeichens (\"aaaa\").");
        else if (IsRepeatedPattern(lower))
            yield return new Problem("pattern", "Avoid repeating a short pattern (\"abcabcabc\").", "Bitte kein kurzes Muster wiederholen (\"abcabcabc\").");

        if (LongestSequence(lower) >= 5)
            yield return new Problem("sequence",
                "Avoid sequences like \"12345\", \"abcde\" or keyboard rows like \"qwertz\".",
                "Bitte keine Folgen wie \"12345\", \"abcde\" oder Tastaturreihen wie \"qwertz\".");
    }

    /// <summary>User name, the parts of the email address, and the service's own words; at least 3 characters each.</summary>
    internal IEnumerable<string> ContextWords(PasswordContext c)
    {
        var words = new List<string>();
        void Add(string? w)
        {
            if (string.IsNullOrWhiteSpace(w)) return;
            foreach (var part in NonLetters().Split(Deleet(w.ToLowerInvariant())))
                if (part.Length >= 3) words.Add(part);
        }
        Add(c.UserName);
        if (c.Email is { } email)
        {
            var at = email.IndexOf('@');
            Add(at > 0 ? email[..at] : email);
            if (at > 0) Add(email[(at + 1)..].Split('.')[0]); // the company domain, not "com"
        }
        foreach (var w in policy.ContextWords) Add(w);
        foreach (var w in c.Words ?? []) Add(w);
        return words.Distinct().OrderByDescending(w => w.Length);
    }

    /// <summary>p@ssw0rd → password: the usual substitutions do not make a weak password strong.</summary>
    internal static string Deleet(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
            sb.Append(ch switch { '0' => 'o', '1' => 'i', '!' => 'i', '3' => 'e', '4' => 'a', '@' => 'a', '5' => 's', '$' => 's', '7' => 't', '+' => 't', _ => ch });
        return sb.ToString();
    }

    internal static bool IsRepeatedPattern(string s)
    {
        for (var period = 1; period <= 4 && period * 3 <= s.Length; period++)
        {
            var repeats = true;
            for (var i = period; i < s.Length && repeats; i++)
                repeats = s[i] == s[i % period];
            if (repeats) return true;
        }
        return false;
    }

    private static readonly string[] KeyboardRows = ["qwertzuiopü", "qwertyuiop", "asdfghjklöä", "asdfghjkl", "yxcvbnm", "zxcvbnm", "1234567890"];

    /// <summary>Longest run of consecutive characters, ascending or descending, alphabetical, numeric or along a keyboard row.</summary>
    internal static int LongestSequence(string s)
    {
        var best = 1;
        int up = 1, down = 1;
        for (var i = 1; i < s.Length; i++)
        {
            up = s[i] == s[i - 1] + 1 ? up + 1 : 1;
            down = s[i] == s[i - 1] - 1 ? down + 1 : 1;
            best = Math.Max(best, Math.Max(up, down));
        }
        foreach (var row in KeyboardRows)
        {
            foreach (var line in new[] { row, new string(row.Reverse().ToArray()) })
                for (var len = Math.Min(line.Length, s.Length); len > best; len--)
                    for (var start = 0; start + len <= line.Length; start++)
                        if (s.Contains(line.AsSpan(start, len), StringComparison.Ordinal)) { best = len; goto nextRow; }
            nextRow:;
        }
        return best;
    }

    [GeneratedRegex(@"[^\p{L}]")]
    private static partial Regex Letters();

    [GeneratedRegex(@"[^\p{L}\p{N}]+")]
    private static partial Regex NonLetters();

    [GeneratedRegex(@"[^\p{L}]+$")]
    private static partial Regex TrailingDigitsAndSymbols();

    [GeneratedRegex(@"(.)\1{3,}")]
    private static partial Regex RepeatedCharacter();

    [GeneratedRegex(@"^(spring|summer|autumn|fall|winter|fruehling|frühling|sommer|herbst|january|february|march|april|may|june|july|august|september|october|november|december|januar|februar|maerz|märz|mai|juni|juli|oktober|dezember)[^\p{L}]*(\d{2}|\d{4})[^\p{L}\d]*$")]
    private static partial Regex SeasonOrMonthWithYear();

    // The most common passwords in public breach lists (incl. German ones), after lower-casing and de-leeting
    private static readonly HashSet<string> CommonPasswords = new(StringComparer.Ordinal)
    {
        "password", "passwort", "passwordpassword", "iloveyou", "princess", "sunshine", "football", "fussball", "baseball", "dragon",
        "monkey", "letmein", "welcome", "willkommen", "master", "qwerty", "qwertz", "hallo", "hallohallo", "schalke", "dortmund",
        "bayern", "ficken", "schatz", "lieblingsmensch", "geheim", "admin", "administrator", "changeme", "secret", "trustno",
        "superman", "batman", "starwars", "pokemon", "shadow", "michael", "jennifer", "computer", "internet", "samsung",
        "whatever", "freedom", "charlie", "lovely", "abcdefghijkl", "passwordi", "passwortpasswort", "zaq", "asdfasdf",
    };
}
