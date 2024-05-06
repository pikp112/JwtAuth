using Microsoft.AspNetCore.Identity;

namespace JwtAuth.Models
{
    public class AppUser : IdentityUser
    {
        public string? FullName { get; set; } = string.Empty;
        public string? RefreshToken { get; set; } = string.Empty;
        public DateTime RefreshTokenExpirtyTime { get; set; } = DateTime.Now;
    }
}