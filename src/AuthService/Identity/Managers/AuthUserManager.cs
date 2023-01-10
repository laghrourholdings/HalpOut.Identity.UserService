using System.Security.Claims;
using CommonLibrary.AspNetCore.Identity.Models;
using CommonLibrary.AspNetCore.Logging.LoggingService;
using CommonLibrary.AspNetCore.ServiceBus.Contracts.Users;
using MassTransit;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthService.Identity.Managers;

public class AuthUserManager : UserManager<User>
{
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly ILoggingService _loggingService;
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
        
        IPublishEndpoint publishEndpoint,
        ILoggingService loggingService, 
        IConfiguration config) 
        : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
    {
        _publishEndpoint = publishEndpoint;
        _loggingService = loggingService;
        _config = config;
    }

    public override async Task<IdentityResult> CreateAsync(
        User user,
        string password)
    {
        var response = await base.CreateAsync(user, password);
        if (response.Succeeded)
        {
            _loggingService.CreateLogHandle(user.LogHandleId, user.Id, "User");
            _publishEndpoint.Publish(new UserCreated(user.Id, user.LogHandleId));
            await base.AddClaimAsync(user, new Claim(UserClaimTypes.LogHandleId,user.LogHandleId.ToString()));
            await base.AddClaimAsync(user, new Claim(UserClaimTypes.UserType, user.UserType));
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