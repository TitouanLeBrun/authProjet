using Microsoft.AspNetCore.Mvc;
using authProjet.Services;

namespace authProjet.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
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
    }
}