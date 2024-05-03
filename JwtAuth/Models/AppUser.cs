using Microsoft.AspNetCore.Identity;

namespace JwtAuth.Models
{
    public class AppUser : IdentityUser
    {
        public string? FullName { get; set; } = string.Empty;
    }
}