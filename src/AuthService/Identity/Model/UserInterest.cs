using CommonLibrary.Core;

namespace AuthService.Identity.Model;

public class UserInterest : IObject, ISuspendable
{
    public Guid Id { get; set; }
    public DateTimeOffset CreationDate { get; set; }
    public string? Descriptor { get; set; }
    public bool IsSuspended { get; set; }
    public DateTimeOffset SuspendedDate { get; set; }
    public Guid SuspendedBy { get; set; }
}