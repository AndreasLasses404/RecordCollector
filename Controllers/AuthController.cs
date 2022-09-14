using Microsoft.AspNetCore.Authorization;
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
        private readonly IUserRepository _repo;

        public AuthController(IConfiguration configuration, IUserRepository repo)
        {
            _configuration = configuration;
            _repo = repo;
        }

        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {
            var userName = _repo.GetMyName();
            return Ok(userName);
        }

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            _repo.CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = request.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public ActionResult<string> Login(UserDto request)
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

            var refreshToken = _repo.GenerateRefreshToken();
            var setRefreshToken = _repo.SetRefreshToken(refreshToken, user);
            Response.Cookies.Append("refreshToken", setRefreshToken.Item1.Token, setRefreshToken.Item2);

            return Ok(token);
        }

        [HttpPost("refresh-token")]
        public ActionResult<string> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (!user.RefreshToken.Token.Equals(refreshToken))
            {
                return Unauthorized("Invalid Refresh Token.");
            }
            else if(user.RefreshToken.Expires < DateTime.Now)
            {
                return Unauthorized("Token Expired.");
            }

            string token = _repo.CreateToken(user);
            var newRefreshToken = _repo.GenerateRefreshToken();
            _repo.SetRefreshToken(newRefreshToken, user);

            return Ok(token);
        }




    }
}
