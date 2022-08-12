using Auth_JWT.JWT;
using Auth_JWT.Model;
using Auth_JWT.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace Auth_JWT.Controller
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IOptions<JwtAuthentication> _jwtAuthentication;
        private readonly UserRepository _userRepository;

        public UserController(IOptions<JwtAuthentication> jwtAuthentication, UserRepository userRepository)
        {
            _jwtAuthentication = jwtAuthentication;
            _userRepository = userRepository;
        }
        [HttpGet]
        public async Task<ActionResult> Get( string email)
        {
            var user = await _userRepository.GetUserAsync(email);
            user.AuthToken = _jwtAuthentication.Value.GenerateToken(user);
            return Ok(user);
        }

  
        [HttpPost("/api/v1/user/register")]
        public async Task<ActionResult> AddUser([FromBody] User user)
        {
            Dictionary<string, string> errors = new Dictionary<string, string>();
            if (user.Name.Length < 3)
            {
                errors.Add("name", "Your username must be at least 3 characters long.");
            }
            if (user.Password.Length < 8)
            {
                errors.Add("password", "Your password must be at least 8 characters long.");
            }
            if (errors.Count > 0)
            {
                return BadRequest(new { error = errors });
            }
            var response = await _userRepository.AddUserAsync(user.Name, user.Email, user.Password);
            if (response.User != null) response.User.AuthToken = _jwtAuthentication.Value.GenerateToken(response.User);
            if (!response.Success)
            {
                return BadRequest(new { error = response.ErrorMessage });
            }
            return Ok(response.User);
        }


       
        [HttpPost("/api/v1/user/login")]
        public async Task<ActionResult> Login([FromBody] User user)
        {
            user.AuthToken = _jwtAuthentication.Value.GenerateToken(user);
            var result = await _userRepository.LoginUserAsync(user);
            return result.User != null ? Ok(new UserResponse(result.User)) : Ok(result);
        }

       
        [HttpPost("/api/v1/user/logout")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<ActionResult> Logout()
        {
            var email = GetUserEmailFromToken(Request);
            if (email.StartsWith("Error")) return BadRequest(email);

            var result = await _userRepository.LogoutUserAsync(email);
            return Ok(result);
        }

      
        [HttpDelete("/api/v1/user/delete")]
        [Authorize(AuthenticationSchemes = "Bearer")]
        public async Task<ActionResult> Delete([FromBody] PasswordObject content)
        {
            var email = GetUserEmailFromToken(Request);
            if (email.StartsWith("Error")) return BadRequest(email);

            var user = await _userRepository.GetUserAsync(email);
            if (!PasswordHashOMatic.Verify(content.Password, user.HashedPassword))
                return BadRequest("Provided password does not match user password.");

            return Ok(await _userRepository.DeletUserAsync(email));
        }

      

        [HttpPost("/api/v1/user/make-admin")]
        public async Task<ActionResult> MakeAdmin([FromBody] User user)
        {
            try
            {
                var newAdmin = await _userRepository.MakeAdminUser(user);
                newAdmin.AuthToken = _jwtAuthentication.Value.GenerateToken(user);
                return Ok(await _userRepository.LoginUserAsync(newAdmin));

            }
            catch (Exception ex)
            {
                return BadRequest($"Error creating an admin user: {ex.Message}");
            }
        }

       
        private static string GetUserEmailFromToken(HttpRequest request)
        {
            var bearer =
                request.Headers.ToArray().First(h => h.Key == "Authorization")
                    .Value.First().Substring(7);

            var jwtHandler = new JwtSecurityTokenHandler();
            var readableToken = jwtHandler.CanReadToken(bearer);
            if (readableToken != true) return "Error: No bearer in the header";

            var token = jwtHandler.ReadJwtToken(bearer);
            var claims = token.Claims;

            var userEmailClaim = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email);

            return userEmailClaim == null ? "Error: Token does not contain an email claim." : userEmailClaim.Value;
        }

        public static async Task<User> GetUserFromTokenAsync(UserRepository _userRepository,
            HttpRequest request)
        {
            var email = GetUserEmailFromToken(request);
            return await _userRepository.GetUserAsync(email);
        }
    }

    /// <summary>
    ///     The mflix client app sends the password as a json object (not string)
    ///     in the request body, like this: {"password": "foo"}.
    ///     This class makes it easy to deserialize it.
    /// </summary>
    public class PasswordObject
    {
        public string Password { get; set; }
    }
}
