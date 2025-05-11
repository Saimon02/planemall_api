using System.ComponentModel.DataAnnotations;

namespace planemall_api.Dtos
{
    public class TokenRequestDto
    {
        [Required]
        public string Token { get; set; }

        [Required]
        public string RefreshToken { get; set; }

    }
}
