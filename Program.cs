using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using PolicyBasedAuthWebApi;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(swagger => 
{
    swagger.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1"
    });

    swagger.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
    {
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
    });

    swagger.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            }, Array.Empty<string>()
        }
    });
});

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("AdminManagerUserPolicy", options => {
        options.RequireAuthenticatedUser();
        options.RequireRole("admin", "manager", "user");
    })
    .AddPolicy("AdminManagerPolicy", options => 
    {
        options.RequireAuthenticatedUser();
        options.RequireRole("admin", "manager");
    })
    .AddPolicy("AdminUserPolicy", options => {
        options.RequireAuthenticatedUser();
        options.RequireRole("admin", "user");
    });

builder.Services.AddDbContext<ApplicationDbContext>(options => {
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDbContext>()
    .AddSignInManager().AddRoles<IdentityRole>();

builder.Services.AddAuthentication(options => {
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options => {
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!))
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

app.MapPost("/account/create", async (string password, string email, string role,
    UserManager<IdentityUser> userManaer) =>
    {
        IdentityUser user = await userManaer.FindByEmailAsync(email);
        if(user != null) return Results.BadRequest(false);

        IdentityUser newUser = new()
        {
            UserName = email,
            PasswordHash = password,
            Email = email
        };
        IdentityResult result = await userManaer.CreateAsync(newUser, password);

        if(!result.Succeeded)
        {
            return Results.BadRequest(false);
        }

        Claim[] userClaims = [
            new Claim(ClaimTypes.Email, email),
            new Claim(ClaimTypes.Role, role)];
        await userManaer.AddClaimsAsync(newUser!, userClaims);
        return Results.Ok(true);
    });

app.MapPost("/account/login", async (string email, string password,
    UserManager<IdentityUser> userManager, 
    SignInManager<IdentityUser> signInManager,
    IConfiguration configuration) =>
    {
        IdentityUser user = await userManager.FindByEmailAsync(email);
        if(user == null) return Results.NotFound();

        SignInResult result = await signInManager.CheckPasswordSignInAsync(user!, password, false);
        if(!result.Succeeded) return Results.BadRequest(null);

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]!));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        
        var token = new JwtSecurityToken(
            issuer: configuration["Jwt:Issuer"], 
            audience: configuration["Jwt:Audience"],
            claims: await userManager.GetClaimsAsync(user),
            expires: DateTime.Now.AddDays(1),
            signingCredentials: credentials);

        return Results.Ok(new JwtSecurityTokenHandler().WriteToken(token));
    });


app.Run();
