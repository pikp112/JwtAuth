using System.ComponentModel.DataAnnotations;

namespace JwtAuth.Dtos
{
    public class CreateRoleDto
    {
        [Required(ErrorMessage = "Role name is required")]
        public string RoleName { get; set; } = null;
    }
}