# Kennwort

**Password rules for .NET as NIST SP 800-63B and the BSI recommend them today: long passwords instead of "one upper-case letter, one digit,
one symbol", and a check against what attackers actually try first: breached passwords (Have I Been Pwned, via k-anonymity), the most common
ones, "Sommer2024!", the user's own name, and keyboard rows. Plugs into ASP.NET Core Identity with one line.**

```text
$ echo "Sommer2024!!!" | kennwort --de
✗ Passwort abgelehnt
  - Jahreszeit oder Monat mit Jahreszahl ("Sommer2024!") gehört zu den ersten Mustern, die Angreifer ausprobieren.
$ echo "P@ssw0rd2024!" | kennwort --de
✗ Passwort abgelehnt
  - Das ist eines der häufigsten Passwörter.
$ echo "correct horse battery staple" | kennwort --de
✗ Passwort abgelehnt
  - Dieses Passwort ist 391-mal in Datenlecks aufgetaucht. Angreifer probieren solche Passwörter zuerst.
$ echo "Blaues Fahrrad unter Linden" | kennwort --de
✓ Passwort akzeptiert (in keinem bekannten Datenleck)
```

> 🇩🇪 **Kurzbeschreibung:** Kennwort setzt die aktuellen Empfehlungen von NIST (SP 800-63B) und BSI (IT-Grundschutz ORP.4) um: Länge statt
> Zeichenklassen-Regeln, keine erzwungenen Wechsel, aber Prüfung gegen bekannte Datenlecks (Have I Been Pwned mit k-Anonymität: nur 5 Zeichen
> des Hashes verlassen den Rechner), häufige Passwörter, „Sommer2024!“, den eigenen Namen und Tastaturfolgen. Alle Meldungen auf Deutsch und
> Englisch, als Validator für ASP.NET Core Identity.

## Why

The old rules ("8 characters, upper and lower case, a digit, a symbol, change every 90 days") produce `Sommer2024!`, which satisfies every one
of them and is among the first guesses of any password-spraying attack. NIST SP 800-63B and the BSI changed their recommendations accordingly:

- **Length matters, composition rules do not.** Allow long passphrases, at least 64 characters, all Unicode.
- **No forced periodic changes**, only after a compromise.
- **Block known-bad passwords:** breached, common, dictionary words and context-specific words such as the user name or the service name.

ASP.NET Core Identity still ships the old composition rules by default and has no breach check. Kennwort replaces them.

## Use it in ASP.NET Core Identity

```csharp
builder.Services.AddIdentityCore<AppUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddKennwort(new PasswordPolicy { MinLength = 12, ContextWords = ["kontor", "musterbank"] });
```

`AddKennwort` registers the validator (it runs on registration, password change and reset), turns off Identity's digit/upper/lower/symbol
rules, and checks against the user's own name and email address. Errors have stable codes (`Kennwort.breached`, `Kennwort.context`, …) so the UI
can show its own text; every problem also carries an English and a German message.

## Rules

| Code | Rule |
|---|---|
| `too-short` / `too-long` | 12 to 128 characters by default (NIST: at least 15 without MFA, 8 with MFA; allow at least 64). Counted in characters after Unicode NFKC normalization, so a decomposed "ä" is one character, as NIST requires. |
| `breached` | Seen in a data breach ([Pwned Passwords](https://haveibeenpwned.com/Passwords), 900+ million hashes). Threshold configurable. |
| `common` | One of the most common passwords, also with appended digits and symbols and leetspeak: `P@ssw0rd2024!` → `password`, `Passwort2024!!` → `passwort`. |
| `season-year` | A season or month with a year: `Sommer2024!`, `Dezember24`, `September2025`. German and English. |
| `context` | Built from the user name, the email address (local part and company domain) or the service's own words, also in leetspeak (`4m4r` → `amar`). |
| `repetition` / `pattern` | `aaaa`, `abcabcabc`, `hahahaha`. |
| `sequence` | 5+ consecutive characters, up or down, alphabetical, numeric or along a German/English keyboard row: `12345`, `zyxwv`, `qwertz`, `asdfgh`. |

What it deliberately does **not** do: require character classes, or estimate "strength" with an entropy formula that rates `P@ssw0rd!` as strong.

## The breach check and privacy

Sending a password, or even its full hash, to a third party would be a data leak of its own. Pwned Passwords uses **k-anonymity**:

1. Kennwort computes the SHA-1 of the password locally: `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8` for "password".
2. Only the first **5 characters** (`5BAA6`) are sent: `GET https://api.pwnedpasswords.com/range/5BAA6`.
3. The API returns the ~1,000 hash suffixes with that prefix and how often each was seen; the match happens locally.
4. With the `Add-Padding` header the response is padded with fake entries (count 0), so its size does not reveal anything either.

The tests check that the request contains the prefix and nothing else. Passwords that already fail the local rules are never sent at all.
If the API is unreachable, the policy decides: accept and log a note (default, so registrations keep working), or reject.

SHA-1 is fine here: it is only a lookup key into a public list, not how the password is stored. Store passwords with Identity's
PBKDF2 hasher (or Argon2/bcrypt), as usual.

## Command line

```bash
dotnet run --project src/Kennwort.Cli -- --user amar --email amar@example.com --word kontor
```

The password is read from a hidden prompt or from stdin, **never from an argument**: command-line arguments end up in the shell history and are
visible to other users in the process list. Options: `--min <n>`, `--offline` (no HIBP), `--de` (German messages). Exit code 0 = accepted,
1 = rejected.

## Tests

57 xUnit tests: the SHA-1 split and the k-anonymity request (prefix only, padding header), parsing of padded responses, every rule with positive
and negative cases (Unicode lengths, leetspeak, German keyboard rows, season patterns), outage behaviour, and the Identity integration on a real
`UserManager` with an in-memory store. A weekly CI job runs against the live API: "correct horse battery staple" must be rejected, a random
passphrase accepted.

Used with [SecureAuth API](https://github.com/karicamar/secure-auth-api), whose login protections (lockout, rate limiting) are the other half of
defending against password guessing.

## License

MIT
