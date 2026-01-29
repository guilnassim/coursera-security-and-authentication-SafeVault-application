using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Application.Interfaces;
using SafeVault.Application.Security;

namespace SafeVault.Web.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _service;
        public UsersController(IUserService service) => _service = service;

        public record SubmitDto(string Username, string Email, string UserPrivateDetail);

        // Secure submission (validates & sanitizes input; stores in app DB)
        [HttpPost("submit")]
        [Authorize(Policy = "UserOrAdmin")]
        public async Task<IActionResult> Submit([FromBody] SubmitDto dto, CancellationToken ct)
        {
            var user = await _service.CreateAsync(dto.Username, dto.Email, dto.UserPrivateDetail, ct);
            // Output with HTML encoding if ever rendered as HTML
            var safeUsernameForDisplay = InputSanitizer.HtmlEncode(user.Username);
            var safeEmailForDisplay = InputSanitizer.HtmlEncode(user.Email);

            return Ok(new { user.Id, Username = safeUsernameForDisplay, Email = safeEmailForDisplay });
        }

        // Admin-only endpoint
        [HttpGet("admin/list")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> List(CancellationToken ct)
        {
            // Minimal example to show RBAC; fetch a snapshot
            return Ok("Admin has access.");
        }

        [HttpGet("admin/user")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> GetUserRecords(string username ,CancellationToken ct)
        {
            var user = await _service.FindByUsernameAsync(username, ct);

            return Ok(user);
        }

        [HttpGet("main")]        
        public async Task<IActionResult> Get(CancellationToken ct)
        {            
            return Ok("User controller.");
        }

    }
}
