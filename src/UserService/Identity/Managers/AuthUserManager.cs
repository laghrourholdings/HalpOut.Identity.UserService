using System.Security.Claims;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.Identity;
using MassTransit;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthService.Identity;

public class AuthUserManager : UserManager<User>
{
    private readonly RoleManager<IdentityRole<Guid>> _roleManager;
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
        
        RoleManager<IdentityRole<Guid>> roleManager,
        IPublishEndpoint publishEndpoint,
        ILoggingService loggingService, 
        IConfiguration config) 
        : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
    {
        _roleManager = roleManager;
        _publishEndpoint = publishEndpoint;
        _loggingService = loggingService;
        _config = config;
    }

    public override async Task<IdentityResult> CreateAsync(
        User? user,
        string password)
    {
        var response = await base.CreateAsync(user, password);
        if (response.Succeeded)
        {
            await base.AddClaimAsync(user, new Claim(UserClaimTypes.LogHandleId,user.LogHandleId.ToString()));
            await base.AddClaimAsync(user, new Claim(UserClaimTypes.Type, user.UserType));
            _loggingService.CreateLogHandle(user.LogHandleId, user.Id, "User");
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