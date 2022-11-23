using AuthService.EFCore;
using AuthService.Identity;
using AuthService.Identity.Managers;
using AuthService.Middleware.Authentication;
using AuthService.Middleware.Authorization;
using CommonLibrary.AspNetCore;
using CommonLibrary.AspNetCore.Identity.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

var  MyAllowSpecificOrigins = "_myAllowSpecificOrigins";

var logger = new LoggerConfiguration().WriteTo.Console();
builder.Services.AddCommonLibrary(builder.Configuration, builder.Logging, logger , MyAllowSpecificOrigins);
builder.Services.AddSwaggerGen();
AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

//Identity
//builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, AuthorizationMiddlewareResultHandler>();
builder.Services.AddScoped<UserManager<User>, AuthUserManager>();
builder.Services.AddDbContext<ServiceDbContext>();
builder.Services.AddIdentity<User, IdentityRole>(options =>
    {
        options.SignIn.RequireConfirmedAccount = true;
        //options.Password.RequiredLength = 8;
        //options.Password.RequireDigit = true;
    })
    .AddSignInManager<UserSignInManager>()
    .AddDefaultTokenProviders()
    .AddEntityFrameworkStores<AuthIdentityDbContext>();
builder.Services.AddDbContext<AuthIdentityDbContext>();
builder.Services.AddAuthentication(UserAuthenticationHandler.Schema).AddScheme<UserAuthenticationOptions, UserAuthenticationHandler>(UserAuthenticationHandler.Schema, null);
var app = builder.Build();
app.UseCommonLibrary(MyAllowSpecificOrigins);
app.UseAuthentication();
if (app.Environment.IsDevelopment()) 
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.Run();