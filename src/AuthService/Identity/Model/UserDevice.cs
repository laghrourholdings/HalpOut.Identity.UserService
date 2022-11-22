using CommonLibrary.Core;

namespace AuthService.Identity.Model;

public class UserDevice : IObject, ISuspendable, IDeletable
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public DateTimeOffset CreationDate { get; set; }
    public string? Descriptor { get; set; }
    public string IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? DeviceName { get; set; }
    public string? DeviceType { get; set; } 
    public string? DeviceModel { get; set; }
    public string? DeviceOs { get; set; }
    public bool IsSuspended { get; set; }
    public DateTimeOffset SuspendedDate { get; set; }
    public Guid SuspendedBy { get; set; }
    public bool IsDeleted { get; set; }
    public DateTimeOffset DeletedDate { get; set; }
    public Guid DeletedBy { get; set; }
}