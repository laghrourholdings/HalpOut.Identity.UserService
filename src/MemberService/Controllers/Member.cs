using Microsoft.AspNetCore.Mvc;

namespace MemberService.Controllers;
[Route("api/v{version:apiVersion}/[controller]")]
[ApiVersion("1.0")]
[ApiController]
public class Member : ControllerBase
{
    
}