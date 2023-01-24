using System.Security.Claims;
using CommonLibrary.AspNetCore.Identity;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.Identity.Models;
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
            _loggingService.CreateLogHandle(user.LogHandleId, user.Id, "User");
            
            //TODO: Isolate to method inside SecuromanService
            var userRoles = await GetRolesAsync(user);
            var rolePrincipal = new RolePrincipal();
            foreach (var userRole in userRoles)
            {
                var role = await _roleManager.FindByNameAsync(userRole);
                if (role == null) continue;
                var roleClaims = await _roleManager.GetClaimsAsync(role);
                foreach (var roleClaim in roleClaims)
                {
                    rolePrincipal.Permissions.Add(
                        new RolePrincipal.UserPermission
                        {
                            Issuer = roleClaim.Issuer,
                            Type = roleClaim.Type,
                            Value = roleClaim.Value
                        });
                }
            }
            var userBadge = new UserBadge()
            {
                LogHandleId = user.LogHandleId,
                UserId = user.Id,
                SecretKey = user.SecretKey,
                RolePrincipal = rolePrincipal
            };
            _publishEndpoint.Publish(new UserCreated(userBadge));
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