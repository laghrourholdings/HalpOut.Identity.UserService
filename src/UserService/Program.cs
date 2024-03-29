using AuthService.Core;
using AuthService.Identity;
using CommonLibrary.AspNetCore.Core;
using CommonLibrary.AspNetCore.Identity.Policies;
using CommonLibrary.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Redis;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

var  MyAllowSpecificOrigins = "7";

var logger = new LoggerConfiguration().WriteTo.Console();
builder.Services.Configure<DatabaseSettings>(builder.Configuration.GetSection(nameof(DatabaseSettings)));
builder.Services.AddCommonLibrary(builder.Configuration, builder.Logging, logger , MyAllowSpecificOrigins,null, false);
builder.Services.AddSwaggerGen();
AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

//Identity
builder.Services.AddScoped<UserManager<User>, AuthUserManager>();
builder.Services.AddIdentity<User, IdentityRole<Guid>>(options =>
    {
        options.ClaimsIdentity.EmailClaimType = UserClaimTypes.Email;
        options.ClaimsIdentity.RoleClaimType = UserClaimTypes.Role;
        options.ClaimsIdentity.SecurityStampClaimType = UserClaimTypes.SecurityStamp;
        options.ClaimsIdentity.UserIdClaimType = UserClaimTypes.Id;
        options.ClaimsIdentity.UserNameClaimType = UserClaimTypes.Name;
        //options.SignIn.RequireConfirmedAccount = true;
        //options.Password.RequiredLength = 8;
        //options.Password.RequireDigit = true;
    })
    .AddSignInManager<UserSignInManager>()
    .AddDefaultTokenProviders()
    .AddEntityFrameworkStores<UserDbContext>()
    ;//.AddClaimsPrincipalFactory<SecuromanUserClaimsPrincipaleFactory>();

builder.Services.AddDbContext<UserDbContext>();
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.Name = SecuromanDefaults.SessionCookie;
    options.ExpireTimeSpan = TimeSpan.FromDays(90);
    options.SlidingExpiration = true;
    options.SessionStore = new UserSessionStore(new RedisCacheOptions
    {
        Configuration = builder.Configuration.GetSection(nameof(DatabaseSettings)).Get<DatabaseSettings>().SessionCacheRedisConfigurationString
    }, builder.Services);
});
builder.Services.AddAuthorization(options => UserPolicyFactory.GetPolicy().Enforce(options));
//builder.Services.AddGrpc();
var app = builder.Build();
app.UseCommonLibrary(MyAllowSpecificOrigins);
if (app.Environment.IsDevelopment()) 
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;

    var context = services.GetRequiredService<UserDbContext>();
    if (context.Database.GetPendingMigrations().Any())
    {
        context.Database.Migrate();
    }
}
app.Run();