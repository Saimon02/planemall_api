using System.ComponentModel.DataAnnotations;

namespace planemall_api.Dtos
{
    public class TokenRequest
    {
        [Required]
        public string Token { get; set; }

        [Required]
        public string RefreshToken { get; set; }

    }
}
