namespace planemall_api.Dtos
{
    public class AuthenticationResultDto
    {
        public string Token { get; set; } 

        public string RefreshToken { get; set; }

        public bool Result { get; set; }

        public List<string> Errors { get; set; }
    }
}
