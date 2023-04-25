using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestAuth.Attributes;
using TestAuth.Models;
using TestAuth.SamplesData;

namespace TestAuth.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly Tenants _tenants;

    public AuthController(IConfiguration configuration, Tenants tenants)
    {
        _configuration = configuration;
        _tenants = tenants;
    }

    [HttpPost]
    public IActionResult RequestToken([FromBody] UserCredentials userCredentials)
    {
        // Check the API key is correct
        Tenant tenant = null;
        string requestAPIKey = Request.Headers["Nitco-api-key"].FirstOrDefault();
        if (!string.IsNullOrEmpty(requestAPIKey))
        {
            tenant = _tenants.Where(t => t.APIKey.ToLower() == requestAPIKey.ToLower()).FirstOrDefault();
        }
        if (tenant == null)
        {
            return Unauthorized();
        }

        // Check the user credentials and return a 400 if they are invalid
        if (!ValidateCredentials(userCredentials))
        {
            return BadRequest();
        }
        // Get the token config from appsettings.json
        string issuer = _configuration["Token:Issuer"];
        int expiryDuration;
        if (!int.TryParse(_configuration["Token:ExpiryDurationMins"], out expiryDuration))
        {
            expiryDuration = 30;
        }
        DateTime expiry = DateTime.UtcNow.Add(TimeSpan.FromMinutes(expiryDuration));

        // Create and sign the token
        var jwtSecurityToken = new JwtSecurityToken(
            issuer: issuer,
            audience: requestAPIKey,
            claims: new[]
            {
                new Claim(ClaimTypes.Name, userCredentials.UserName),
                new Claim("User_ID", userCredentials.User_ID),
                new Claim("OrgName", userCredentials.OrgName),
                new Claim("Branch_ID", userCredentials.Branch_ID),
            },
            expires: expiry,
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tenant.SecretKey)),
                SecurityAlgorithms.HmacSha256
            )
        );
        jwtSecurityToken.Header.Add("kid", requestAPIKey);
        var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

        // return the token and when it expires
        return Ok(new
        {
            AccessToken = token,
            Expiry = expiry
        });

    }

    private bool ValidateCredentials(UserCredentials credentials)
    {
        // Not for production !!!
        return true;
    }
}
