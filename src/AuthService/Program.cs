using AuthService.EFCore;
using AuthService.Identity;
using AuthService.Identity.Authorization;
using AuthService.Identity.Managers;
using AuthService.Identity.Models;
using AuthService.Identity.Stores;
using CommonLibrary.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Redis;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

var  MyAllowSpecificOrigins = "7";

var logger = new LoggerConfiguration().WriteTo.Console();
builder.Services.AddCommonLibrary(builder.Configuration, builder.Logging, logger , MyAllowSpecificOrigins);
builder.Services.AddCommonLibraryLoggingService();
builder.Services.AddSwaggerGen();
AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

//Identity
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, UserAuthorizationMiddlewareResultHandler>();
builder.Services.AddScoped<UserManager<User>, AuthUserManager>();
builder.Services.AddIdentity<User, IdentityRole<Guid>>(options =>
    {
        //options.SignIn.RequireConfirmedAccount = true;
        //options.Password.RequiredLength = 8;
        //options.Password.RequireDigit = true;
    })
    .AddSignInManager<UserSignInManager>()
    .AddDefaultTokenProviders()
    .AddEntityFrameworkStores<UserDbContext>();

builder.Services.AddDbContext<UserDbContext>();

// builder.Services.AddIdentityCore<User>(options =>
//     {
//         //options.SignIn.RequireConfirmedAccount = true;
//         //options.Password.RequiredLength = 8;
//         //options.Password.RequireDigit = true;
//     })
//     .AddRoles<IdentityRole>()
//     .AddSignInManager<UserSignInManager>()
//     .AddDefaultTokenProviders()
//     .AddEntityFrameworkStores<AuthIdentityDbContext>();
// 

//builder.Services.AddScoped<IUserClaimsPrincipalFactory<User>, UserClaimsPrincipleFactory>();
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "Identity.Session";
    options.ExpireTimeSpan = TimeSpan.FromDays(90);
    options.SlidingExpiration = true;
    options.SessionStore = new UserSessionStore(new RedisCacheOptions
    {
        Configuration = "localhost:6379"
    }, builder.Services);
    //new UserSessionStore(builder.Services.BuildServiceProvider());
});
builder.Services.AddAuthorization(options => Policies.UserPolicies(options));

var app = builder.Build();
app.UseAuthentication();
app.UseCommonLibrary(MyAllowSpecificOrigins);
app.UseAuthorization();
if (app.Environment.IsDevelopment()) 
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.Run();