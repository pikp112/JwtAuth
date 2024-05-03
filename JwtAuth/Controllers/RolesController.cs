using JwtAuth.Dtos;
using JwtAuth.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuth.Controllers
{
    [Authorize(Roles = "Admin, Manager")]
    [Route("api/[controller]")]
    [ApiController]
    public class RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager) : ControllerBase
    {
        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
        {
            if (string.IsNullOrEmpty(createRoleDto.RoleName))
                return BadRequest("Role name is required");

            var roleExist = await roleManager.RoleExistsAsync(createRoleDto.RoleName);
            if (roleExist)
                return BadRequest("Role already exists");

            var role = await roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName));
            if (role.Succeeded)
                return Ok("Role created successfully");

            return BadRequest(role.Errors);
        }

        [AllowAnonymous]
        [HttpGet]
        public async Task<IActionResult> GetRoles()
        {
            var roles = await roleManager.Roles.AsNoTracking().Select(r => new RoleResponseDto
            {
                Id = r.Id,
                Name = r.Name,
                TotalUsers = userManager.GetUsersInRoleAsync(r.Name!).Result.Count
            }).ToListAsync();

            return Ok(roles);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound("Role not found");

            var result = await roleManager.DeleteAsync(role);
            if (result.Succeeded)
                return Ok("Role deleted successfully");

            return BadRequest(result.Errors);
        }

        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignDto roleAssignDto)
        {
            var user = await userManager.FindByIdAsync(roleAssignDto.UserId);
            if (user == null)
                return NotFound("User not found");

            var role = await roleManager.FindByIdAsync(roleAssignDto.RoleId);
            if (role == null)
                return NotFound("Role not found");

            var result = await userManager.AddToRoleAsync(user, role.Name!);
            if (result.Succeeded)
                return Ok("Role assigned successfully");

            return BadRequest(result.Errors);
        }
    }
}