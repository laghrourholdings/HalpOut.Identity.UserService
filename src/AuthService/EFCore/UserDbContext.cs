using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Settings;
using CommonLibrary.ModelBuilders;
using Microsoft.EntityFrameworkCore;

namespace AuthService.EFCore;

public class UserDbContext : DbContext
{
    private readonly IConfiguration _configuration;

    public UserDbContext(DbContextOptions<UserDbContext> opt, IConfiguration configuration) : base(opt)
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