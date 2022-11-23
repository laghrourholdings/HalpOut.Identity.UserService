using AuthService.EFCore;
using AuthService.Identity.Managers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace AuthService.Identity.Stores;

public class UserSessionStore : ITicketStore
{
    private readonly ILogger _logger;
    private readonly AuthUserManager _userManager;
    private readonly IConfiguration _configuration;
    private readonly ServiceDbContext _serviceDbContext;
    private readonly UserSignInManager _userSignInManager;

    public UserSessionStore(
        ILogger logger,
        AuthUserManager userManager,
        IConfiguration configuration)
    {
        _logger = logger;
        _userManager = userManager;
        _configuration = configuration;
    }

    public UserSessionStore(IServiceProvider provider)
    {

        _serviceDbContext = provider.GetService<ServiceDbContext>();
        _userManager = provider.GetService<AuthUserManager>();
        _userSignInManager = provider.GetService<UserSignInManager>();
    }

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        throw new NotImplementedException();
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        ticket.Principal
        throw new NotImplementedException();
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        throw new NotImplementedException();
    }

    public Task RemoveAsync(string key)
    {
        throw new NotImplementedException();
    }
}