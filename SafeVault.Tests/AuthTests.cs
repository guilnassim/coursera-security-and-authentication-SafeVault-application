
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Infrastructure.Persistence;
using SafeVault.Infrastructure.Security;
using System.IdentityModel.Tokens.Jwt;
using Xunit;

public class AuthTests
{
    private static async Task<(UserManager<IdentityUser> um, RoleManager<IdentityRole> rm, JwtTokenService jwt, IdentityUser user)> SetupAsync()
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddDbContext<IdentityDb>(o => o.UseInMemoryDatabase("TestIdentity_" + Guid.NewGuid()));
        services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<IdentityDb>()
            .AddDefaultTokenProviders();
        services.AddLogging();
        var sp = services.BuildServiceProvider();
        var um = sp.GetRequiredService<UserManager<IdentityUser>>();
        var rm = sp.GetRequiredService<RoleManager<IdentityRole>>();
        await rm.CreateAsync(new IdentityRole("Admin"));
        await rm.CreateAsync(new IdentityRole("User"));

        var user = new IdentityUser { UserName = "tester", Email = "tester@example.com" };
        var res = await um.CreateAsync(user, "Str0ng!Password!2025");
        Assert.True(res.Succeeded);
        await um.AddToRoleAsync(user, "User");

        var jwt = new JwtTokenService("issuer", "audience", "super_secret_key_that_is_at_least_32_chars_long!!", TimeSpan.FromMinutes(30));
        return (um, rm, jwt, user);
    }

    [Fact]
    public async Task Login_Issues_Jwt_With_Roles()
    {
        var (um, _, jwt, user) = await SetupAsync();
        var ok = await um.CheckPasswordAsync(user, "Str0ng!Password!2025");
        Assert.True(ok);

        var roles = await um.GetRolesAsync(user);
        var token = jwt.CreateToken(user.Id, user.UserName!, roles);
        var handler = new JwtSecurityTokenHandler();
        var parsed = handler.ReadJwtToken(token);
        Assert.Contains(parsed.Claims, c => c.Type == System.Security.Claims.ClaimTypes.Role && c.Value == "User");
    }
}
