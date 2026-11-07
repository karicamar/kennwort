using System.Text;
using Kennwort;

Console.OutputEncoding = Encoding.UTF8;

if (args.Length > 0 && args[0] is "-h" or "--help")
{
    Console.WriteLine("""
        Kennwort: check a password against NIST SP 800-63B / BSI rules and Have I Been Pwned (k-anonymity)

        Usage: kennwort [options]          The password is read from a hidden prompt or from stdin, never from the
                                           command line (arguments end up in shell history and process lists).
          --user <name>       user name to check against
          --email <address>   email address to check against
          --word <word>       service or company word to check against (repeatable)
          --min <n>           minimum length (default 12)
          --offline           skip the Have I Been Pwned check
          --de                messages in German

        Exit codes: 0 = accepted, 1 = rejected, 2 = error.
        Example:  echo "correct horse battery staple" | kennwort --user amar --word kontor
        """);
    return 0;
}

string? user = null, email = null;
var words = new List<string>();
var min = 12;
var offline = false;
var german = false;
try
{
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--user": user = args[++i]; break;
            case "--email": email = args[++i]; break;
            case "--word": words.Add(args[++i]); break;
            case "--min": min = int.Parse(args[++i], System.Globalization.CultureInfo.InvariantCulture); break;
            case "--offline": offline = true; break;
            case "--de": german = true; break;
            default:
                Console.Error.WriteLine(args[i].StartsWith('-')
                    ? $"Unknown option {args[i]}"
                    : "Do not pass the password as an argument; it is read from the prompt or stdin.");
                return 2;
        }
    }
}
catch (Exception ex) when (ex is IndexOutOfRangeException or FormatException)
{
    Console.Error.WriteLine("Invalid arguments: " + ex.Message);
    return 2;
}

var password = Console.IsInputRedirected ? Console.In.ReadLine() : ReadHidden(german ? "Passwort: " : "Password: ");
if (string.IsNullOrEmpty(password))
{
    Console.Error.WriteLine("No password given.");
    return 2;
}

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
http.DefaultRequestHeaders.UserAgent.ParseAdd("Kennwort/1.0 (+https://github.com/karicamar/kennwort)");
var checker = new PasswordChecker(new PasswordPolicy { MinLength = min, CheckBreaches = !offline }, offline ? null : new PwnedPasswordsClient(http));
var result = await checker.CheckAsync(password, new PasswordContext(user, email, words));

if (result.Accepted)
{
    Write(german ? "✓ Passwort akzeptiert" : "✓ Password accepted", ConsoleColor.Green);
    Console.WriteLine(result.BreachCount is 0 ? (german ? " (in keinem bekannten Datenleck)" : " (not in any known breach)") : "");
}
else
{
    Write(german ? "✗ Passwort abgelehnt\n" : "✗ Password rejected\n", ConsoleColor.Red);
    foreach (var p in result.Problems)
        Console.WriteLine($"  - {(german ? p.German : p.English)}");
}
foreach (var n in result.Notes)
    Write($"  ! {n}\n", ConsoleColor.Yellow);
return result.Accepted ? 0 : 1;

static string ReadHidden(string prompt)
{
    Console.Write(prompt);
    var sb = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; continue; }
        if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
    }
    Console.WriteLine();
    return sb.ToString();
}

static void Write(string text, ConsoleColor color)
{
    var old = Console.ForegroundColor;
    Console.ForegroundColor = color;
    Console.Write(text);
    Console.ForegroundColor = old;
}
