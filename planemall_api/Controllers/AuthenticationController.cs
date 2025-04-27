using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using planemall_api.Configurations.Jwt;
using planemall_api.Data.PostgreSql.RefreshTokenData.Interface;
using planemall_api.Dtos;
using planemall_api.Interfaces.Models;
using planemall_api.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace planemall_api.Controllers
{
    [Route("api/auth")]
    [EnableCors("FlutterPolicy")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly TokenValidationParameters _tokenValidationParameters;

        private readonly IPostgresUser _user_repo;
        private readonly IPostgresRefreshToken _postgresRefreshToken_repo;

        public AuthenticationController(IConfiguration configuration, TokenValidationParameters tokenValidationParameters, IPostgresUser user_repo, IPostgresRefreshToken postgresRefreshToken_repo)
        {
            _configuration = configuration;
            _tokenValidationParameters = tokenValidationParameters;

            _user_repo = user_repo;
            _postgresRefreshToken_repo = postgresRefreshToken_repo;
        }


        #region Post Method

        [HttpPost("register")]
        public async Task<ActionResult<AuthenticationResultDto>> Register(UserDto request)
        {
            var result = new AuthenticationResultDto()
            {
                Token = string.Empty,
                RefreshToken = string.Empty,
                Result = false,
                Errors = new List<string>()
            };

            if ((await _user_repo.GetUserByEmailAsync(request.email)) is null)
            {
                this.CreatePasswordHash(request.password, out byte[] passwordHash, out byte[] passwordSalt);

                User user = new User()
                {
                    Email = request.email,
                    Username = request.username,
                    Password_Hash = passwordHash,
                    Password_Salt = passwordSalt
                };

                if (!await _user_repo.InsertUserAsync(user))
                    return BadRequest(false);

                result = await CreateToken(user);

                return Ok(result);
            }
            else
            {
                result.Errors.Add("Account already exists");
                return BadRequest(result);
            }
        }

        [HttpPost("login")]
        public async Task<ActionResult<AuthenticationResultDto>> Login([FromBody] UserDto request)
        {
            var result = new AuthenticationResultDto()
            {
                Token = string.Empty,
                RefreshToken = string.Empty,
                Result = false,
                Errors = new List<string>()
            };

            try
            {
                User? user;

                user = await _user_repo.GetUserByEmailAsync(request.email);

                if(user == null)
                {
                    user = await _user_repo.GetUserByUsernameAsync(request.username);
                }

                if (user != null)
                {
                    if (!this.VerifyPasswordHash(request.password, user.Password_Hash, user.Password_Salt))
                    {
                        result.Errors.Add("The password is not correct");
                        return BadRequest(result);
                    }

                    result = await CreateToken(user);
                    return Ok(result);
                }
                else
                {
                    result.Errors.Add("User not found");
                    return NotFound(result);
                }
            }
            catch (Exception ex)
            {
                result?.Errors.Add(ex.Message);
                return BadRequest(result);
            }
        }

        [HttpPost]
        [Route("refreshtoken")]
        public async Task<ActionResult<AuthenticationResultDto>> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    return Ok(await VerifyAndGenerateToken(tokenRequest));
                }

                return BadRequest(new AuthenticationResultDto()
                {
                    Errors = new List<string>()
                    {
                        "Invalid parameters",
                    },
                    Result = false
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new AuthenticationResultDto()
                {
                    Errors = new List<string>()
                    {
                        "Server Error",
                    },
                    Result = false
                });
            }
        }

        #endregion


        #region Private Functions

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private async Task<AuthenticationResultDto?> CreateToken(User user)
        {
            try
            {
                var jwtConfig = new JwtConfig()
                {
                    SecretToken = _configuration.GetSection("JwtConfig:SecretToken").Value!,
                    ExpireTimeFrame = TimeSpan.Parse(_configuration.GetSection(key: "JwtConfig:ExpireTimeFrame").Value!)
                };

                var TokenHandler = new JwtSecurityTokenHandler();

                var tokenDescriptor = new SecurityTokenDescriptor()
                {
                    Subject = new ClaimsIdentity
                    (
                        new[]
                        {
                            new Claim(type: "Id", value: user.Id.ToString()),
                            new Claim(type: JwtRegisteredClaimNames.Sub, value: user.Email),
                            new Claim(type: JwtRegisteredClaimNames.Email, value: user.Email),
                            new Claim(type: JwtRegisteredClaimNames.Jti, value: Guid.NewGuid().ToString()),
                            new Claim(type: JwtRegisteredClaimNames.Iat, value: DateTime.Now.ToUniversalTime().ToString())
                        }
                    ),
                    Expires = DateTime.UtcNow.Add(jwtConfig.ExpireTimeFrame),
                    SigningCredentials = new SigningCredentials
                    (
                        new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(jwtConfig.SecretToken)),
                        SecurityAlgorithms.HmacSha256
                    )
                };

                var token = TokenHandler.CreateToken(tokenDescriptor: tokenDescriptor);
                if(token == null)
                {
                    return new AuthenticationResultDto()
                    {
                        Result = false,
                        Errors = new List<string>() { "Server Error, token not generated" }
                    };
                }

                var jwtToken = TokenHandler.WriteToken(token);
                if(jwtToken == null)
                {
                    return new AuthenticationResultDto()
                    {
                        Result = false,
                        Errors = new List<string>() { "Server Error, jwtToken not generated" }
                    };
                }

                var refreshToken = new RefreshToken()
                {
                    JwtId = token.Id,
                    Token = RandomStringGeneration(23), //Generate a refresh token
                    AddedDate = DateTime.UtcNow,
                    ExpiryDate = DateTime.UtcNow.AddMonths(6),
                    IsRevoked = false,
                    IsUsed = false,
                    UserId = user.Id
                };

                await _postgresRefreshToken_repo.InsertRefreshTokenAsync(refreshToken);

                return new AuthenticationResultDto()
                {
                    Result = true,
                    Token = jwtToken,
                    RefreshToken = refreshToken.Token
                };
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        private string RandomStringGeneration(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmopqrstuvwxyz_";

            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private async Task<AuthenticationResultDto?> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            try
            {
                var jwtTokenHandler = new JwtSecurityTokenHandler();

                _tokenValidationParameters.ValidateLifetime = false; //for testing

                var tokenInVerification = 
                    jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                    if(result == false)
                        return null;   
                }

                //var tokenUtcExpireDate = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp)?.Value;
                //if(tokenUtcExpireDate == null)
                //    return null;

                //I ignore the token'expire date
                //var utcExpiryDate = long.Parse(tokenUtcExpireDate);
                //var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                //if(expiryDate <= DateTime.UtcNow)
                //{
                //    return new AuthenticationResultDto() 
                //    { 
                //        Result = false,
                //        Errors = new List<string>()
                //        {
                //            "Expire token"
                //        }
                //    };
                //}

                var storedToken = await _postgresRefreshToken_repo.GetRefreshTokenByTokenAsync(tokenRequest.RefreshToken);

                if(storedToken == null || storedToken.IsUsed || storedToken.IsRevoked)
                {
                    return new AuthenticationResultDto()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid tokens"
                        }
                    };
                }

                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)?.Value;

                if(storedToken.JwtId != jti)
                {
                    return new AuthenticationResultDto()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid tokens"
                        }
                    };
                }

                if(storedToken.ExpiryDate < DateTime.UtcNow)
                {
                    return new AuthenticationResultDto()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Expired tokens"
                        }
                    };
                }

                storedToken.IsUsed = true;
                await _postgresRefreshToken_repo.UpdateRefreshTokenAsync(storedToken);

                var dbUser = await _user_repo.GetUserByIdAsync(storedToken.UserId);
                if(dbUser == null)
                {
                    return new AuthenticationResultDto()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Invalid userId"
                        }
                    };
                }

                return await CreateToken(dbUser);

            }
            catch (Exception ex)
            {
                return new AuthenticationResultDto()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Server Error"
                    }
                };
            }
        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();

            return dateTimeVal;
        }

        #endregion
    }
}
