namespace JwtAuth.Dtos
{
    public class TokenDto
    {
        public string RefreshToken { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }
}