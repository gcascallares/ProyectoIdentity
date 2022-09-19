using System.ComponentModel.DataAnnotations;

namespace ProyectoIdentity.Models
{
    public class AccesoViewModel
    {
        [Required(ErrorMessage ="Ingrese un email")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "Ingrese una contraseña")]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [Display(Name = "Recordar datos?")]
        public bool RememberMe { get; set; }
    }
}
