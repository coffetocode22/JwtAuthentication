using JwtAuthentication.Models;
using JwtAuthentication.Services.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly IUserService _userService;
        private readonly IAuthentificationService _authentificationService;
        private static User user = new User();

        public UserController(IUserService userService, IAuthentificationService authentificationService)
        {
            _userService = userService;
            _authentificationService = authentificationService;
        }

        [HttpPost("/register")]
        public async Task<ActionResult<string>> Create(UserDto newUser)
        {
            _userService.CreatePasswordHash(newUser.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.UserName = newUser.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok("User created succesfully");
        }

        [HttpPost("/login")]
        public async Task<ActionResult<string>> Login(UserDto logInUser)
        {
            if (logInUser.UserName != user.UserName)
            {
                return NotFound();
            }
            if (!_userService.VerifyPasswordHash(logInUser.Password, user.PasswordHash, user.PasswordSalt))
            {
                return Unauthorized("User not authorizeed");
            }

            var token = _authentificationService.CreateToken(user);
            return Ok(String.Format("Token: {0}", token));
        }
    }
}
