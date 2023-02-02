using System.Security.Claims;
using CommonLibrary.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthService.Identity;

public class SecuromanUserClaimsPrincipaleFactory : UserClaimsPrincipalFactory<User, IdentityRole<Guid>>
{
    
    
    public Task<ClaimsPrincipal> CreateAsync(User user)
    {
        return Task.Factory.StartNew(() =>
        {
            var identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
            identity.AddClaim(new Claim(UserClaimTypes.Id, user.Id.ToString()));
            identity.AddClaim(new Claim(UserClaimTypes.Email, user.Email));
            identity.AddClaim(new Claim(UserClaimTypes.Name, user.UserName));
            identity.AddClaim(new Claim(UserClaimTypes.LogHandleId, user.LogHandleId.ToString()));
            identity.AddClaim(new Claim(UserClaimTypes.Type, user.UserType));
            //var roles = UserManager.GetRolesAsync(user);
            
            var principle = new ClaimsPrincipal(identity);

            return principle;
        });
    }

    public SecuromanUserClaimsPrincipaleFactory(UserManager<User> userManager, RoleManager<IdentityRole<Guid>> roleManager, IOptions<IdentityOptions> options) 
        : base(userManager, roleManager, options)
    {
    }
}