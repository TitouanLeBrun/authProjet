using Microsoft.AspNetCore.Mvc;
using authProjet.Services;
using Microsoft.AspNetCore.Identity;
using authProjet.Models;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace authProjet.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthController(IAuthService authService, UserManager<ApplicationUser> userManager)
        {
            _authService = authService;
            _userManager = userManager;
        }

        public record LoginRequest(string Email, string Password);
        public record RegisterRequest(string Email, string Password, string FirstName, string LastName);

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var result = await _authService.LoginAsync(request.Email, request.Password);
            if (!result.success)
            {
                return Unauthorized(result.token);
            }

            return Ok(new { token = result.token });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterAsync(request.Email, request.Password, request.FirstName, request.LastName);
            if (!result.success)
            {
                return BadRequest(result.message);
            }

            return Ok(result.message);
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                return BadRequest("Invalid confirmation request.");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest("User not found.");
            }

            var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);
            var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);

            var result = await _userManager.ConfirmEmailAsync(user, decodedToken);
            if (result.Succeeded)
            {
                return Ok("E-mail confirmé avec succès.");
            }

            return BadRequest("Erreur lors de la confirmation de l'e-mail.");
        }
    }
}