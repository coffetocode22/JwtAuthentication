using JwtAuthentication.Models;

namespace JwtAuthentication.Services.Interfaces
{
    public interface IAuthentificationService
    {
        public string CreateToken(User user);
    }
}
