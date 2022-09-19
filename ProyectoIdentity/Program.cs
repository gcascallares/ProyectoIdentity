using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using ProyectoIdentity.Datos;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options => 
    options.UseSqlServer(builder.Configuration.GetConnectionString("ConexionSql"))
);

//agregamos el service identity

builder.Services.AddIdentity<IdentityUser, IdentityRole>().
    AddEntityFrameworkStores<ApplicationDbContext>().
    AddDefaultTokenProviders();

//autenticacion facebook
builder.Services.AddAuthentication().AddFacebook(options =>
{
    options.AppId = "747871359746779";
    options.AppSecret = "6714f3ebd7a4785bde43083cfca843d9";
});

//autenticacion google
builder.Services.AddAuthentication().AddGoogle(options =>
{
    options.ClientId = "451192887583-h4t03vimj4fe47n4v0q1rrrcprefa3mh.apps.googleusercontent.com";
    options.ClientSecret = "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";
});

// Add services to the container.
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

//se agrega autenticacion
app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
