using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Kennwort;

/// <summary>
/// ASP.NET Core Identity password validator: runs on registration, password change and reset. Problems become
/// IdentityErrors with stable codes ("Kennwort.breached") so the UI can show its own text, or the German message.
/// </summary>
public sealed class KennwortPasswordValidator<TUser>(PasswordChecker checker) : IPasswordValidator<TUser> where TUser : class
{
    public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password)
    {
        if (string.IsNullOrEmpty(password))
            return IdentityResult.Failed(new IdentityError { Code = "Kennwort.too-short", Description = "Password is required." });

        var context = new PasswordContext(await manager.GetUserNameAsync(user).ConfigureAwait(false), await manager.GetEmailAsync(user).ConfigureAwait(false));
        var result = await checker.CheckAsync(password, context).ConfigureAwait(false);
        return result.Accepted
            ? IdentityResult.Success
            : IdentityResult.Failed(result.Problems.Select(p => new IdentityError { Code = "Kennwort." + p.Code, Description = p.English }).ToArray());
    }
}

public static class KennwortServiceExtensions
{
    /// <summary>
    /// Adds the Kennwort policy to Identity and turns off Identity's composition rules (digit, upper/lower case, symbol),
    /// which NIST SP 800-63B recommends against. Length is enforced by the policy.
    /// </summary>
    public static IdentityBuilder AddKennwort(this IdentityBuilder builder, PasswordPolicy? policy = null, HttpClient? http = null)
    {
        policy ??= new PasswordPolicy();
        builder.Services.Configure<IdentityOptions>(o =>
        {
            o.Password.RequireDigit = false;
            o.Password.RequireLowercase = false;
            o.Password.RequireUppercase = false;
            o.Password.RequireNonAlphanumeric = false;
            o.Password.RequiredUniqueChars = 1;
            o.Password.RequiredLength = Math.Min(policy.MinLength, o.Password.RequiredLength);
        });
        builder.Services.AddSingleton(policy);
        builder.Services.AddSingleton<IBreachedPasswordChecker>(_ =>
            new PwnedPasswordsClient(http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(5) }));
        builder.Services.AddSingleton(sp => new PasswordChecker(policy, sp.GetRequiredService<IBreachedPasswordChecker>()));
        // The validator is generic over the app's user type, which is only known at runtime
        builder.Services.AddScoped(typeof(IPasswordValidator<>).MakeGenericType(builder.UserType),
            typeof(KennwortPasswordValidator<>).MakeGenericType(builder.UserType));
        return builder;
    }
}
