using System.ComponentModel.DataAnnotations;

namespace Application.DTO.Request.Identity
{
     public class LoginUserRequestDTO
    {
        [EmailAddress]
        [RegularExpression("[@^\\t\\r\\n]+@[^@ \\t\\r\\n]+\\.[^@ \\t\\r\n]+", ErrorMessage = "Invalid email format")]

        public string Email { get; set; }
        [Required]
        [RegularExpression("^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[#?!@$ %^&*-]).{8,}$", ErrorMessage="Your password is incorrect")]
        [MinLength(8), MaxLength(100)]

        public string Password { get; set; }
    }
}
