using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using planemall_api.Configurations.Jwt;
using planemall_api.Data.PostgreSql.RefreshTokenData.Interface;
using planemall_api.Data.PostgreSql.RefreshTokenData.Repository;
using planemall_api.Interfaces.Models;
using planemall_api.Models.PostgreSql;
using planemall_api.Postgresql;
using System.Text;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(builder.Configuration.GetConnectionString("WebApiDatabase")));

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

#region Scopes

builder.Services.AddScoped<IPostgresUser, PostgresUserRepo>();
builder.Services.AddScoped<IPostgresRefreshToken, PostgresRefreshTokenRepo>();

#endregion

#region Logger

//var logger = new LoggerConfiguration()
//    .ReadFrom.Configuration(builder.Configuration)
//    .CreateLogger();

//builder.Logging.AddSerilog(logger);

builder.Host.UseSerilog(configureLogger: (context, configuration) =>
{
    configuration.ReadFrom.Configuration(context.Configuration);
});

#endregion

#region Cors Policy

builder.Services.AddCors(o => o.AddPolicy("FlutterPolicy", builder =>
{
    builder.AllowAnyOrigin()
           .AllowAnyMethod()
           .AllowAnyHeader();
}));

#endregion

#region Authorization

builder.Services.Configure<JwtConfig>(builder.Configuration.GetSection("JwtConfig"));

var key = Encoding.ASCII.GetBytes(builder.Configuration.GetSection("JwtConfig:SecretToken").Value!);
var tokenValidationParameter = new TokenValidationParameters()
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKey = new SymmetricSecurityKey(key),
    ValidateIssuer = false, //false for dev
    ValidateAudience = false, //false for dev
    RequireExpirationTime = false, //false for dev -- needs to be updated when refresh token is set
    ValidateLifetime = true
};

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

}).AddJwtBearer(jwt => {

    jwt.SaveToken = true;
    jwt.TokenValidationParameters = tokenValidationParameter;
});

builder.Services.AddSingleton(tokenValidationParameter);

#endregion

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

app.UseCors();

app.Run();
