using System.Security.Claims;

namespace TestAuth.Services.UserService;

public class UserService
{
    private readonly IHttpContextAccessor httpContextAccessor;

    public UserService(IHttpContextAccessor httpContextAccessor)
    {
        this.httpContextAccessor = httpContextAccessor;
    }

    public string GetUserName()
    {
        if (httpContextAccessor == null || httpContextAccessor?.HttpContext == null)
            return string.Empty;
        return httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
    }
}
