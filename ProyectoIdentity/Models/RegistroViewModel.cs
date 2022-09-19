using System.ComponentModel.DataAnnotations;

namespace ProyectoIdentity.Models
{
    public class RegistroViewModel
    {
        [Required(ErrorMessage ="Ingrese un email")]
        [EmailAddress]
        public string Email { get; set; }

        [Required(ErrorMessage = "Ingrese una contraseña")]
        [StringLength(20, ErrorMessage = "El {0} debe tener al menos {2} caracteres de logitud", MinimumLength = 5)]
        [DataType(DataType.Password)]
        [Display(Name = "Contraseña")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Ingrese confirmacion de contraseña")]
        [Compare("Password", ErrorMessage = "La contraseña y la confirmacion no coinciden")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirmar Contraseña")]
        public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "Ingrese un nombre")]
        public string Nombre { get; set; }
        public string Url { get; set; }
        public int CodigoPais { get; set; }
        public string Telefono { get; set; }

        [Required(ErrorMessage = "Ingrese un Pais")]
        public string Pais { get; set; }
        public string Ciudad { get; set; }
        public string Direccion { get; set; }

        [Required(ErrorMessage = "Ingrese una fecha de nacimiento")]
        public DateTime FechaNacimiento { get; set; }

        [Required(ErrorMessage = "Ingrese un estado")]
        public bool Estado { get; set; }
    }
}
