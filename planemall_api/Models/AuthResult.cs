namespace planemall_api.Models
{
    public class AuthResult
    {
        public int Id { get; set; }

        public string UserId { get; set; }

        public string Token { get; set; }

        public string RefreshToken { get; set; }

        public string JwtId { get; set; }
    }
}
