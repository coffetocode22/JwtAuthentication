using JwtAuthentication.Services.Interfaces;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthentication.Services
{
    public class UserService : IUserService
    {
        public void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        public bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var newPasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return newPasswordHash.SequenceEqual(passwordHash);
            }

        }
    }
}
