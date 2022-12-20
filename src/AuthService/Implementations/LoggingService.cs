using CommonLibrary.AspNetCore.Contracts.Users;
using CommonLibrary.AspNetCore.Identity.Model;
using CommonLibrary.AspNetCore.Logging;
using CommonLibrary.AspNetCore.ServiceBus;
using MassTransit;

namespace AuthService.Implementations;

public class LoggingService : ILoggingService
{
    private readonly IPublishEndpoint _publishEndpoint;
    private readonly IConfiguration _config;
    private readonly Serilog.ILogger _logger;

    public LoggingService(
        IPublishEndpoint publishEndpoint,
        IConfiguration config,
        Serilog.ILogger logger)
    {
        _publishEndpoint = publishEndpoint;
        _config = config;
        _logger = logger;
    }
    public void InformationToBusLog(string message, Guid logHandleId)
    {
        _logger.InformationToBusLog(_config,message, logHandleId, _publishEndpoint);
    }

    public async void CreateUserLog(
        User user)
    {
        var message = new ServiceBusPayload<User>
        {
            Descriptor = $"User created {user.Id}",
            Contract = nameof(UserCreated),
            Subject = user
        };
        await _publishEndpoint.Publish(new UserCreated(message));
    }
}