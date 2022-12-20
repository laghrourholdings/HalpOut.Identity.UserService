using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Logging;
using MassTransit;

namespace AuthService.Implementations;

public interface ILoggingService
{
    public void InformationToBusLog(
        string message,
        Guid logHandleId);

    public void CreateUserLog(
        User user);
}