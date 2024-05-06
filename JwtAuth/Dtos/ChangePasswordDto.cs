﻿using System.ComponentModel.DataAnnotations;

namespace JwtAuth.Dtos
{
    public class ChangePasswordDto
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string CurrentPassword { get; set; } = string.Empty;

        [Required]
        [MinLength(6)]
        public string NewPassword { get; set; } = string.Empty;
    }
}