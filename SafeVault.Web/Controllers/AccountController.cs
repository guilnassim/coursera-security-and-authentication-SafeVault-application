using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Application.Security;
using SafeVault.Infrastructure.Security;

namespace SafeVault.Web.Controllers
{
    [ApiController]
    [Route("/[controller]")]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly JwtTokenService _jwt;

        public AccountController(UserManager<IdentityUser> um, SignInManager<IdentityUser> sm, JwtTokenService jwt)
        {
            _userManager = um; _signInManager = sm; _jwt = jwt;
        }

        public record RegisterDto(string Username, string Email, string Password, string Role);
        public record LoginDto(string Username, string Password);

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {

            // Identity internally hashes passwords (PBKDF2 by default)
            var user = new IdentityUser { UserName = InputSanitizer.SanitizeStrict(dto.Username), Email = InputSanitizer.SanitizeStrict(dto.Email), EmailConfirmed = true };
            var createRes = await _userManager.CreateAsync(user, dto.Password);
            if (!createRes.Succeeded) return BadRequest(createRes.Errors);

            if (!string.IsNullOrWhiteSpace(dto.Role) && await _userManager.IsInRoleAsync(user, dto.Role) == false)
                await _userManager.AddToRoleAsync(user, dto.Role);

            return Ok(new { message = "Registered" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _userManager.FindByNameAsync(dto.Username);
            if (user is null) return Unauthorized();

            if (!await _userManager.CheckPasswordAsync(user, dto.Password))
                return Unauthorized();

            var roles = await _userManager.GetRolesAsync(user);
            var token = _jwt.CreateToken(user.Id, user.UserName!, roles);
            return Ok(new { token });
        }


        [HttpGet("register")]
        public IActionResult Register() => View();


        [HttpGet("login")]
        public IActionResult Login() => View();

        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }



    }
}
