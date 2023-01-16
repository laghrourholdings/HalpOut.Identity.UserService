using CommonLibrary.Core;

namespace AuthService.Identity;

public class UserSession : IDeletable
{
    public Guid Id { get; set; }
    public UserDevice Device { get; set; }
    public string CacheKey { get; set; }
    public DateTimeOffset CreationDate { get; set; }
    public DateTimeOffset? ExpirationDate { get; set; }
    public byte[] PrivateKey { get; set; }
    public byte[] PublicKey { get; set; }
    
    public byte[] AuthenticationTicket { get; set; }
    public bool IsDeleted { get; set; } = false;
    public DateTimeOffset DeletedDate { get; set; }
    public Guid DeletedBy { get; set; } = Guid.Empty;
    public Guid UserId { get; set; }
}