using AuthService.Identity.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthService.Identity.Managers;

/*public class UserClaimsPrincipleFactory : IUserClaimsPrincipalFactory<User>
{
    public Task<ClaimsPrincipal> CreateAsync(User user)
    {
        return Task.Factory.StartNew(() =>
        {
            var identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
            identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
            identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
            var principle = new ClaimsPrincipal(identity);

            return principle;
        });
    }
}*/

public class UserSignInManager : SignInManager<User>
{
    public UserSignInManager(
        UserManager<User> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<User> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<User>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<User> confirmation) : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {
    }
    
    public override Task<SignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool shouldLockout)
    {
        // here goes the external username and password look up
        return base.PasswordSignInAsync(userName, password, isPersistent, shouldLockout);

        if (userName.ToLower() == "username" && password.ToLower() == "password")
        {
            return base.PasswordSignInAsync(userName, password, isPersistent, shouldLockout);
        }
        else
        {
            return Task.FromResult(SignInResult.Failed);
        }
    }
}