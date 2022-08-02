using JwtAuthentication.Models;
using JwtAuthentication.Services.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthentication.Services
{
    public class AuthentificationService : IAuthentificationService
    {
        public readonly IConfiguration _configuration;

        public AuthentificationService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string CreateToken(User user)
        {
            int tokenValidityInMinutes = Convert.ToInt16(_configuration.GetSection("Jwt:TokenValidityInMinutes").Value);
            string secret = _configuration.GetSection("Jwt:Secret").Value;

            List<Claim> claims = new List<Claim> 
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Role, "Admin")
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
