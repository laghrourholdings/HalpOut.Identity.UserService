using CommonLibrary.AspNetCore.Contracts.Users;
using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.AspNetCore.ServiceBus;
using MassTransit;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using ILogger = Serilog.ILogger;

namespace AuthService.Identity.Managers;

public class AuthUserManager : UserManager<User>
{
    private readonly IPublishEndpoint _publishEndpoint;
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
        IPublishEndpoint publishEndpoint, ILogger seriLogger, IConfiguration config) : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
    {
        _publishEndpoint = publishEndpoint;
        _logger = seriLogger;
        _config = config;
    }

    public override async Task<IdentityResult> CreateAsync(
        User user,
        string password)
    {
        _logger.Information("Creating user {@user}", user);
        var response = await base.CreateAsync(user, password);
        if (response.Succeeded)
        {
            var message = new ServiceBusPayload<User>
            {
                Descriptor = $"User created {user.Id}",
                Contract = nameof(UserCreated),
                Subject = user
            };
            await _publishEndpoint.Publish(new UserCreated(message));
        }

        return response;
    }

    public override Task<IdentityResult> UpdateAsync(
        User user)
    {
        _logger.InformationToBusLog(_config, $"Updated user {user.Id}", user.LogHandleId, _publishEndpoint);
        return base.UpdateAsync(user);
    }
}