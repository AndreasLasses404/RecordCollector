using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RecordCollector.Dtos;
using RecordCollector.Models;
using RecordCollector.Repository;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace RecordCollector.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;
        private readonly IAuthRepository _repo;

        public AuthController(IConfiguration configuration, IAuthRepository repo)
        {
            _configuration = configuration;
            _repo = repo;
        }


        [HttpPost("register")]
        public async  Task<ActionResult<User>> Register(UserDto request)
        {
            _repo.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if(user.UserName != request.UserName)
            {
                return BadRequest("User not found");
            }

            if(!_repo.VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password");
            }

            string token = _repo.CreateToken(user);
            return Ok(token);
        }




    }
}
