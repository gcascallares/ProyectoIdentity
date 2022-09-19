using System.ComponentModel.DataAnnotations;

namespace ProyectoIdentity.Models
{
    public class OlvidoPasswordViewModel
    {
        [Required(ErrorMessage ="Ingrese un email")]
        [EmailAddress]
        public string Email { get; set; }
    }
}
