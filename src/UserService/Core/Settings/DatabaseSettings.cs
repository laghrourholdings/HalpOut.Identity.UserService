namespace AuthService.Core;

public class DatabaseSettings
{
    public string UserPostgresConnectionString { get; init; }
    public string SessionCacheRedisConfigurationString { get; init; }
}