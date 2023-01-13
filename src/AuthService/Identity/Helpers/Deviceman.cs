using AuthService.Identity.Models;
using CommonLibrary.Utilities;

namespace AuthService.Identity.Helpers;

public static class Deviceman
{
    public static UserDevice CreateDevice(string userAgent, string remoteIpAddress, Guid userId)
    {
        var uaParser = UAParser.Parser.GetDefault();
        var clientInfo = uaParser.Parse(userAgent);
        var device = new UserDevice
        {
            Id = default,
            CreationDate = DateTimeOffset.Now,
            Descriptor = null,
            IpAddress = remoteIpAddress,
            UserAgent = userAgent,
            DeviceName = clientInfo.Device.Model,
            DeviceType = clientInfo.UserAgent.Family,
            DeviceModel = $"{clientInfo.UserAgent.Major}.{clientInfo.UserAgent.Minor}.{clientInfo.UserAgent.Patch}",
            DeviceOs = clientInfo.OS.ToString(),
            Hash = Hashing.GenerateMD5Hash($"{userAgent}.{remoteIpAddress}.{userId}"),
            IsSuspended = false,
            SuspendedDate = default,
            SuspendedBy = default,
            IsDeleted = false,
            DeletedDate = default,
            DeletedBy = default
        };
        return device;
    }
        


public static string GetDeviceHash(string userAgent, string remoteIpAddress, Guid userId)
    => Hashing.GenerateMD5Hash($"{userAgent}.{remoteIpAddress}.{userId}");
       
}