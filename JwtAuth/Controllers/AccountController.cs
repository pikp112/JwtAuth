using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using JwtAuth.Dtos;
using JwtAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RestSharp;

namespace JwtAuth.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration) : ControllerBase
    {
        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = new AppUser
            {
                Email = registerDto.Email,
                FullName = registerDto.FullName,
                UserName = registerDto.Email
            };

            var result = await userManager.CreateAsync(user, registerDto.Password);

            if (!result.Succeeded)
                return BadRequest(result.Errors);

            if (!registerDto.Roles.Any())
                await userManager.AddToRoleAsync(user, "User");
            else
                foreach (var role in registerDto.Roles)
                    await userManager.AddToRoleAsync(user, role);

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "Account created successfully"
            });
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await userManager.FindByEmailAsync(loginDto.Email);

            if (user == null)
                return Unauthorized(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "User not found with the provided email"
                });

            var result = await userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!result)
                return Unauthorized(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Invalid password"
                });

            var token = GenerateToken(user);
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(configuration["JwtSettings:refreshTokenExpiryTime"], out var minutes) ? minutes : 10;
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpirtyTime = DateTime.Now.AddMinutes(minutes);
            await userManager.UpdateAsync(user);

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Token = token,
                Message = "Login successful",
                RefreshToken = refreshToken
            });
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber)
        }

        [Authorize]
        [HttpGet("details")]
        public async Task<IActionResult> UserDetails()
        {
            var user = await userManager.FindByEmailAsync(User.Identity?.Name);

            if (user == null)
                return NotFound(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });

            return Ok(new UserDetailDto
            {
                Id = user.Id,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccesFailedCount = user.AccessFailedCount,
                FullName = user.FullName,
                Roles = [.. await userManager.GetRolesAsync(user)]
            });
        }

        [HttpGet]
        public async Task<IActionResult> GetUsers()
        {
            var users = await userManager.Users.Select(x => new UserDetailDto
            {
                Id = x.Id,
                Email = x.Email,
                PhoneNumber = x.PhoneNumber,
                PhoneNumberConfirmed = x.PhoneNumberConfirmed,
                AccesFailedCount = x.AccessFailedCount,
                FullName = x.FullName,
                Roles = userManager.GetRolesAsync(x).Result.ToArray()
            }).ToListAsync();

            return Ok(users);
        }

        [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
        {
            var user = await userManager.FindByEmailAsync(forgotPasswordDto.Email);

            if (user is null)
            {
                return Ok(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });
            }

            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"https://localhost:4200/reset-password?email={forgotPasswordDto.Email}&token={WebUtility.UrlEncode(token)}";

            var request = new RestRequest
            {
                Method = Method.Post,
                RequestFormat = DataFormat.Json
            };
            request.AddHeader("Authorization", "Bearer " + configuration["SendGrid:ApiKey"]);
            request.AddJsonBody(new
            {
                personalizations = new[]
                {
                    new
                    {
                        to = new[]
                        {
                            new
                            {
                                email = forgotPasswordDto.Email
                            }
                        },
                        subject = "Reset your password"
                    }
                },
                from = new
                {
                    email = "mailtrap@demoemailtrap.com"
                },
                to = new[]
                {
                    new
                    {
                        email = forgotPasswordDto.Email
                    }
                },
                content = new[]
                {
                    new
                    {
                        type = "text/html",
                        value = $"<a href='{resetLink}'>Reset Password</a>"
                    }
                },
                template_id = configuration["SendGrid:TemplateId"],
                template_variables = new
                {
                    resetLink
                }
            });

            var response = new RestClient(configuration["SendGrid:ApiUrl"]).Execute(request);

            if (response.IsSuccessStatusCode)
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Reset password link sent to your email"
                });

            return BadRequest(new AuthResponseDto()
            {
                IsSuccess = false,
                Message = response.Content.ToString()
            });
        }

        [AllowAnonymous]
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPassordDto)
        {
            var user = await userManager.FindByEmailAsync(resetPassordDto.Email);
            resetPassordDto.Token = WebUtility.UrlDecode(resetPassordDto.Token);

            if (user is null)
                return NotFound(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });

            var result = await userManager.ResetPasswordAsync(user, resetPassordDto.Token, resetPassordDto.NewPassword);

            if (result.Succeeded)
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Password reset successful"
                });

            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = result.Errors.FirstOrDefault()?.Description
            });
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordDto changePasswordDto)
        {
            var user = await userManager.FindByEmailAsync(changePasswordDto.Email);
            if (user is null)
                return NotFound(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "User not found"
                });

            var result = await userManager.ChangePasswordAsync(user, changePasswordDto.CurrentPassword, changePasswordDto.NewPassword);

            if (result.Succeeded)
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Password changed successfully"
                });

            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = result.Errors.FirstOrDefault()?.Description
            });
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken(TokenDto tokenDto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var principal = GetPrincipalFromExpiredTone(tokenDto.Token);
            var user = await userManager.FindByEmailAsync(tokenDto.Email);

            if (principal is null || user is null || user.RefreshToken != tokenDto.RefreshToken || user.RefreshTokenExpirtyTime < DateTime.Now)
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Invalid token"
                });

            var newJwtToken = GenerateToken(user);
            var newRefreshToken = GenerateRefreshToken();
            _ = int.TryParse(configuration["JwtSettings:refreshTokenExpiryTime"], out var minutes) ? minutes : 10;
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpirtyTime = DateTime.Now.AddMinutes(minutes);
            await userManager.UpdateAsync(user);
            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Token = newJwtToken,
                RefreshToken = newRefreshToken,
                Message = "Token refreshed successfully"
            });
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredTone(string token)
        {
            var tokenParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetSection("JwtSetting:securityKey").Value!)),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenParameters, out var securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        private string GenerateToken(AppUser user)
        {
            var tokentHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(configuration["JwtSettings:securityKey"]!);

            var roles = userManager.GetRolesAsync(user).Result;

            var claims = new List<Claim>
            {
                new (JwtRegisteredClaimNames.Email, user.Email??string.Empty),
                new (JwtRegisteredClaimNames.Name, user.FullName??string.Empty),
                new (JwtRegisteredClaimNames.NameId, user.Id ?? string.Empty),
                new (JwtRegisteredClaimNames.Aud, configuration["JwtSettings:validAudience"]!),
                new (JwtRegisteredClaimNames.Iss, configuration["JwtSettings:validIssuer"]!)
            };

            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokentHandler.CreateToken(tokenDescriptor);
            return tokentHandler.WriteToken(token);
        }
    }
}