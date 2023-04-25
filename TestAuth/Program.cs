using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text;
using TestAuth.Filters;
using TestAuth.Models;
using TestAuth.SamplesData;
using TestAuth.Services.UserService;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        Description = "Test Call OAuth2 with swagger multi tenants",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer"
    });
    options.OperationFilter<SecurityRequirementsOperationFilter>();
    options.OperationFilter<SwaggerHeaderFilter>();
});
builder.Services.AddScoped<Tenants>();

builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<UserService,UserService>();
var tenants = builder.Services.BuildServiceProvider()?.GetService<Tenants>();
var accessor1 = builder.Services.BuildServiceProvider()?.GetService<IHttpContextAccessor>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Specify what in the JWT needs to be checked
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            // Specify the valid issue from appsettings.json
            ValidIssuer = builder.Configuration.GetSection("Token:Issuer").Value,

            // Specify the tenant API keys as the valid audiences
            ValidAudiences = tenants.Select(t => t.APIKey).ToList(),

            IssuerSigningKeyResolver = (string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
            {
                List<SecurityKey> keys = new List<SecurityKey>();
                if (accessor1?.HttpContext.Request.Headers["Nitco-api-key"].FirstOrDefault() != kid)
                {
                    return keys;
                }
                Tenant tenant = tenants.Where(t => t.APIKey == kid).FirstOrDefault();
                if (tenant != null)
                {
                    var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tenant.SecretKey));
                    keys.Add(signingKey);
                }
                return keys;
            }
        };
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();


app.MapControllers();

app.Run();
