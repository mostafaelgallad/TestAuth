﻿namespace TestAuth.Models;

public class Tenant
{
    public string TenantId { get; set; }
    public string SecretKey { get; set; }
    public string APIKey { get; set; }
}
