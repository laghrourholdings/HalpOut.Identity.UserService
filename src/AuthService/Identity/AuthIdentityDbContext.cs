using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Settings;
using CommonLibrary.ModelBuilders;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Identity;

public class AuthIdentityDbContext : IdentityDbContext<User, IdentityRole, string>
{
    private readonly IConfiguration _configuration;

    public AuthIdentityDbContext(DbContextOptions options,IConfiguration configuration)
        : base(options)
    {
        _configuration = configuration;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        ServiceSettings serviceSettings = _configuration.GetSection(nameof(ServiceSettings)).Get<ServiceSettings>() ?? throw new InvalidOperationException("ServiceSettings is null");
        optionsBuilder.UseNpgsql(serviceSettings.PostgresConnectionString);
    }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.BuildCommonLibrary();
        base.OnModelCreating(modelBuilder);
    }
}