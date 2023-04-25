using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using TestAuth.Services.UserService;

namespace TestAuth.Controllers;


[Route("api/[controller]")]
[ApiController, Authorize]
public class ValuesController : ControllerBase
{
    private readonly UserService userService;

    public ValuesController(UserService userService)
    {
        this.userService = userService;
    }
    [HttpGet("TestAuthMethod")]
    public IActionResult TestAuthMethod()
    {
        return Ok(userService.GetUserName());
    }
}
