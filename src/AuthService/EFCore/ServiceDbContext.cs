using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Settings;
using CommonLibrary.Logging;
using CommonLibrary.ModelBuilders;
using Microsoft.EntityFrameworkCore;

namespace AuthService.EFCore;

public class ServiceDbContext : DbContext
{
    private readonly IConfiguration _configuration;

    public ServiceDbContext(DbContextOptions<ServiceDbContext> opt, IConfiguration configuration) : base(opt)
    {
            _configuration = configuration;
    }
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        ServiceSettings serviceSettings = _configuration.GetSection(nameof(ServiceSettings)).Get<ServiceSettings>() ?? throw new InvalidOperationException("ServiceSettings is null");
        optionsBuilder.UseNpgsql(serviceSettings.UserPostgresConnectionString);
    }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.BuildCommonLibrary();
    }
    public DbSet<UserSession> UserSessions { get; set; }
    public DbSet<UserDetail> UserDetails { get; set; }
    public DbSet<UserInterest> UserInterests { get; set; }
    public DbSet<UserDevice> UserDevices { get; set; }
}