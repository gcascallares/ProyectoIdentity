using System.ComponentModel.DataAnnotations;

namespace ProyectoIdentity.Models
{
    public class RecuperaPasswordViewModel
    {
        [Required(ErrorMessage = "Ingrese un email")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "Ingrese una contraseña")]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Ingrese confirmacion de contraseña")]
        [Compare("Password", ErrorMessage = "La contraseña y la confirmacion no coinciden")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirmar Contraseña")]
        public string ConfirmPassword { get; set; }
        public string Code { get; set; }
    }
}
