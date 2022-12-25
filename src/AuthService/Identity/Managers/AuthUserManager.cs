using CommonLibrary.AspNetCore.Contracts.Users;
using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.AspNetCore.Logging.LoggingService;
using CommonLibrary.AspNetCore.ServiceBus;
using MassTransit;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using ILogger = Serilog.ILogger;

namespace AuthService.Identity.Managers;

public class AuthUserManager : UserManager<User>
{
    private readonly ILoggingService _loggingService;
    private readonly ILogger _logger;
    private readonly IConfiguration _config;

    public AuthUserManager(
        IUserStore<User> store,
        IOptions<IdentityOptions> optionsAccessor,
        IPasswordHasher<User> passwordHasher,
        IEnumerable<IUserValidator<User>> userValidators,
        IEnumerable<IPasswordValidator<User>> passwordValidators,
        ILookupNormalizer keyNormalizer,
        IdentityErrorDescriber errors,
        IServiceProvider services,
        ILogger<UserManager<User>> logger,
        ILoggingService loggingService,
         ILogger seriLogger, IConfiguration config) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
    {
        _loggingService = loggingService;
        _logger = seriLogger;
        _config = config;
    }

    public override async Task<IdentityResult> CreateAsync(
        User user,
        string password)
    {
        var response = await base.CreateAsync(user, password);
        if (response.Succeeded)
        {
            
        }
        return response;
    }

    public override Task<IdentityResult> UpdateAsync(
        User user)
    {
        _loggingService.Verbose($"User updated", user.LogHandleId);
        return base.UpdateAsync(user);
    }
}