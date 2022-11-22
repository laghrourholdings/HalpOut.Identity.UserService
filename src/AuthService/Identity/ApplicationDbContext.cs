using CommonLibrary.AspNetCore.Settings;
using CommonLibrary.ModelBuilders;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthService.Identity;

public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    private readonly IConfiguration _configuration;

    public ApplicationDbContext(DbContextOptions options,IConfiguration configuration)
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