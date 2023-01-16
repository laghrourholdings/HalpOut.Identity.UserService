using CommonLibrary.Logging;
using Microsoft.AspNetCore.Identity;

namespace AuthService.Identity;

public sealed class User : IdentityUser<Guid>, ILoggable
{
    public Guid LogHandleId { get; set; }
    public string UserType { get; set; }
    public byte[] SecretKey { get; set; }
    public ICollection<UserDevice> UserDevices { get; set; } = new HashSet<UserDevice>();
    public ICollection<UserSession> UserSessions { get; set; } = new HashSet<UserSession>();

}