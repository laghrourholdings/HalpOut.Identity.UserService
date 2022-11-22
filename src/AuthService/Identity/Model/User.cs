using CommonLibrary.Logging;
using Microsoft.AspNetCore.Identity;

namespace AuthService.Identity.Model;

public class User : IdentityUser, ILoggable
{
    public virtual Guid LogHandleId { get; set; }
    public virtual Guid SessionId { get; set; }
}