using AuthService.EFCore;
using AuthService.Identity;
using AuthService.Identity.Model;
using AuthService.Middleware.Authorization;
using CommonLibrary.AspNetCore;
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
builder.Services.AddSingleton<
    IAuthorizationMiddlewareResultHandler, AuthorizationMiddlewareResultHandler>();
builder.Services.AddDbContext<ServiceDbContext>();
builder.Services.AddIdentity<User, UserRole>(options =>
    {
        options.SignIn.RequireConfirmedAccount = true;
    })
    .AddEntityFrameworkStores<AuthIdentityDbContext>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ElevatedRights", policy =>
        policy.RequireRole("Administrator", "PowerUser", "BackupAdministrator"));
});


var app = builder.Build();
app.UseCommonLibrary(MyAllowSpecificOrigins);
app.UseAuthentication();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
app.Run();