using System.Security.Claims;
using Xunit;

public class AuthorizationTests
{
    [Fact]
    public void NonAdmin_Principal_Fails_AdminOnly()
    {
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "basic"),
            new Claim(ClaimTypes.Role, "User")
        }, "TestAuth");

        var principal = new ClaimsPrincipal(identity);
        var isAdmin = principal.IsInRole("Admin");
        Assert.False(isAdmin);
    }

    [Fact]
    public void Admin_Principal_Passes_AdminOnly()
    {
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "root"),
            new Claim(ClaimTypes.Role, "Admin")
        }, "TestAuth");

        var principal = new ClaimsPrincipal(identity);
        var isAdmin = principal.IsInRole("Admin");
        Assert.True(isAdmin);
    }
}
