using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ProyectoIdentity.Models;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace ProyectoIdentity.Controllers
{
    public class CuentasController : Controller
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        public readonly IConfiguration _configuration;

        public CuentasController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Registro()
        {
            RegistroViewModel registroVM = new RegistroViewModel();
            return View(registroVM);
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Registro(RegistroViewModel rgViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = new AppUsuario { 
                    UserName = rgViewModel.Email,
                    Email = rgViewModel.Email,
                    Nombre = rgViewModel.Nombre,
                    Ciudad = rgViewModel.Ciudad,
                    Direccion = rgViewModel.Direccion,
                    Telefono = rgViewModel.Telefono,
                    Url = rgViewModel.Url,
                    CodigoPais = rgViewModel.CodigoPais,
                    FechaNacimiento = rgViewModel.FechaNacimiento,
                    Estado = rgViewModel.Estado,
                    Pais = rgViewModel.Pais
                };
                var resultado = await _userManager.CreateAsync(usuario, rgViewModel.Password);

                if (resultado.Succeeded)
                {
                    await _signInManager.SignInAsync(usuario, isPersistent: false);

                    return RedirectToAction("Index", "Home");
                }
                ValidarErrores(resultado);
            }
            return View(rgViewModel);
        }

        public void ValidarErrores(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(String.Empty, error.Description);
            }
        }

        [HttpGet]
        public IActionResult Acceso()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Acceso(AccesoViewModel accViewModel)
        {
            if (ModelState.IsValid)
            {
                var resultado = await _signInManager.PasswordSignInAsync(accViewModel.Email, accViewModel.Password, accViewModel.RememberMe, lockoutOnFailure: false);

                if (resultado.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError(String.Empty, "Acceso invalido");
                    return View(accViewModel);
                }
            }
            return View(accViewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SalirAplicacion()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        [HttpGet]
        public IActionResult OlvidoPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> OlvidoPassword(OlvidoPasswordViewModel opViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _userManager.FindByEmailAsync(opViewModel.Email);
                if (usuario == null)
                {
                    return RedirectToAction("ConfirmacionOlvidoPassword");
                }
                var codigo = await _userManager.GeneratePasswordResetTokenAsync(usuario);
                var urlRetorno = Url.Action("ResetPassword", "Cuentas", new {userId = usuario.Id, code = codigo}, protocol: HttpContext.Request.Scheme);

                Console.WriteLine("Token reseteo password: " + urlRetorno + "\"");
                return RedirectToAction("ConfirmacionOlvidoPassword");

            }
            return View(opViewModel);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmacionOlvidoPassword()
        {
            return View();
        }
        //funcion para recuperar contraseña
        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            return code == null ? View("Error") : View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(RecuperaPasswordViewModel rpViewModel)
        {
            if (ModelState.IsValid)
            {
                var usuario = await _userManager.FindByEmailAsync(rpViewModel.Email);
                if (usuario == null)
                {
                    return RedirectToAction("ConfirmacionRecuperaPassword");
                }
                var resultado = await _userManager.ResetPasswordAsync(usuario, rpViewModel.Code, rpViewModel.Password);
                if (resultado.Succeeded)
                {
                    return RedirectToAction("ConfirmacionRecuperaPassword");
                }
                ValidarErrores(resultado);

            }
            return View(rpViewModel);
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ConfirmacionRecuperaPassword()
        {
            return View();
        }

        //Configuracion acceso externo: Facebook, google, etc
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult AccesoExterno(string proveedor, string returnurl = null)
        {
            var urlRedireccion = Url.Action("AccesoExternoCallback", "Cuentas", new {ReturnUrl = returnurl});
            var propiedades = _signInManager.ConfigureExternalAuthenticationProperties(proveedor, urlRedireccion);
            var test = Challenge(propiedades, proveedor);
            return test;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> AccesoExternoCallback(string returnurl = null, string error = null)
        {
            returnurl = returnurl ?? Url.Content("~/");
            if(error != null)
            {
                ModelState.AddModelError(string.Empty, $"Error en el acceso externo {error}");
                return View(nameof(Acceso));
            }
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return RedirectToAction(nameof(Acceso));
            }
            //Acceder con usuario en proveedor externo
            var resultado = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
            if (resultado.Succeeded)
            {
                //Actualiar los token de acceso
                await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
                return LocalRedirect(returnurl);
            }
            else
            {
                //Si el usuario no tiene cuenta pregunta para crear una
                ViewData["ReturnUrl"] = returnurl;
                ViewData["NombreProveedor"] = info.ProviderDisplayName;
                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var nombre = info.Principal.FindFirstValue(ClaimTypes.Name);
                return View("ConfirmacionAccesoExterno", new ConfirmacionAccesoExternoViewModel { Email = email, Name = nombre});
            }
        }

        //[HttpPost]
        //[AllowAnonymous]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> ConfirmacionAccesoExterno(ConfirmacionAccesoExternoViewModel caeViewModel, string returnurl = null)
        //{
        //    returnurl = returnurl ?? Url.Content("~/");
        //    if (ModelState.IsValid)
        //    {
        //        //Obtener informacion del user del proveedor externo
        //        /*var info = await _signInManager.GetExternalLoginInfoAsync();
        //        if(info == null)
        //        {
        //            return View("Error");
        //        }*/
        //        //validar user existente y retornar token

        //        /*var user = await _userManager.FindByEmailAsync("gcascallares@vecfleet.io");

        //        if (user != null)
        //        {
        //            var authClaims = new List<Claim>
        //            {
        //            new Claim(ClaimTypes.Name, user.UserName),
        //            new Claim(ClaimTypes.Email, user.Email)
        //            };

        //            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));

        //            var token = new JwtSecurityToken(
        //            issuer: _configuration["JWT:ValidIssuer"],
        //            audience: _configuration["JWT:ValidAudience"],
        //            claims: authClaims,
        //            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        //            );

        //            var Token = new JwtSecurityTokenHandler().WriteToken(token);

        //        }
        //        else
        //        {
        //            throw new Exception("Invalid email or password");
        //        }*/

        //        //Crear user inexistente
        //        var usuario = new AppUsuario { UserName = caeViewModel.Email, Email = caeViewModel.Email, Nombre = caeViewModel.Name };
        //        var resultado = await _userManager.CreateAsync(usuario);
        //        if (resultado.Succeeded)
        //        {
        //            //resultado = await _userManager.AddLoginAsync(usuario, info);
        //            if (resultado.Succeeded)
        //            {
        //                await _signInManager.SignInAsync(usuario, isPersistent: false);
        //                //await _signInManager.UpdateExternalAuthenticationTokensAsync(info);
        //                //var tokenTest = await _userManager.GetAuthenticationTokenAsync(usuario, "Microsoft", "test");
        //                //var tokent2 = await _userManager.GenerateUserTokenAsync(usuario, null, null);
        //                return LocalRedirect(returnurl);
        //            }
        //        }
        //        //ValidarErrores(resultado);
        //    }
        //    ViewData["ReturnUrl"] = returnurl;
        //    return View(caeViewModel);
        //}

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConfirmacionAccesoExterno(ConfirmacionAccesoExternoViewModel caeViewModel, string returnurl = null)
        {
            returnurl = returnurl ?? Url.Content("~/");
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(caeViewModel.Email);

                if (user == null)
                {
                    user = new AppUsuario { UserName = caeViewModel.Email, Email = caeViewModel.Email, Nombre = caeViewModel.Name };
                    var resultado = await _userManager.CreateAsync(user);

                }
                var authClaims = new List<Claim>
                    {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(ClaimTypes.Email, user.Email)
                    };

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));

                var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                var Token = new JwtSecurityTokenHandler().WriteToken(token);
                await _signInManager.SignInAsync(user, isPersistent: false);
                return LocalRedirect(returnurl);
            }
            ViewData["ReturnUrl"] = returnurl;
            return View(caeViewModel);
        }
    }
}
