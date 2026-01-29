using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Application.Interfaces;
using SafeVault.Application.Services;
using SafeVault.Infrastructure.Persistence;
using SafeVault.Infrastructure.Repositories;
using SafeVault.Infrastructure.Security;
using System.Security.Claims;
using System.Text;



var builder = WebApplication.CreateBuilder(args);

// --- Config (use secrets/env in production) ---
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "SafeVaultIssuer";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "SafeVaultAudience";
var jwtKey = builder.Configuration["Jwt:Key"] ?? "CHANGE_ME_TO_A_LONG_RANDOM_SECRET";
var tokenLifetimeMinutes = int.TryParse(builder.Configuration["Jwt:Lifetime"], out var m) ? m : 60;

// --- DbContexts (InMemory) ---
builder.Services.AddDbContext<AppDbContext>(o => o.UseInMemoryDatabase("SafeVaultAppDb"));
builder.Services.AddDbContext<IdentityDb>(o => o.UseInMemoryDatabase("SafeVaultIdentityDb"));

// --- Identity ---
builder.Services.AddIdentity<IdentityUser, IdentityRole>(opts =>
{
    // Hardening password policy (OWASP A03)
    opts.Password.RequireDigit = true;
    opts.Password.RequireLowercase = true;
    opts.Password.RequireUppercase = true;
    opts.Password.RequireNonAlphanumeric = true;
    opts.Password.RequiredLength = 12;
})
.AddEntityFrameworkStores<IdentityDb>()
.AddDefaultTokenProviders();

// --- JWT AuthN ---
var keyBytes = Encoding.UTF8.GetBytes(jwtKey);
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
            ClockSkew = TimeSpan.FromMinutes(5),
            RoleClaimType = ClaimTypes.Role,
            NameClaimType = ClaimTypes.NameIdentifier
        };
    });




// --- Authorization (RBAC) ---
builder.Services.AddAuthorization(opts =>
{
    opts.AddPolicy("AdminOnly", p => p.RequireRole("Admin"));
    opts.AddPolicy("UserOrAdmin", p => p.RequireRole("User", "Admin"));
});

// --- DI for application services ---
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddSingleton(new JwtTokenService(jwtIssuer, jwtAudience, jwtKey, TimeSpan.FromMinutes(tokenLifetimeMinutes)));

builder.Services.AddControllers();

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();



var app = builder.Build();

// Global error handling (simplified)
app.UseExceptionHandler("/error");
app.Map("/error", (HttpContext ctx) => Results.Problem("An error occurred."));

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'";
    await next();
});

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();


app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapControllers();

// Seed roles (Admin, User, Guest)
using (var scope = app.Services.CreateScope())
{
    var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    foreach (var role in new[] { "Admin", "User", "Guest" })
    {
        if (!await roleMgr.RoleExistsAsync(role))
            await roleMgr.CreateAsync(new IdentityRole(role));
    }
}


app.Run();
