using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuth.Dtos;
using JwtAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

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

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Token = token,
                Message = "Login successful"
            });
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