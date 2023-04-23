using Microsoft.AspNetCore.Authentication.JwtBearer;
using MinimalJwt.Models;
using MinimalJwt.Service;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Description = "Bearer Authentication with JWT Token",
        Type = SecuritySchemeType.Http
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            new List<string>()
        }
    });
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateActor = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});
builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSingleton<IMovieService, MovieService>();
builder.Services.AddSingleton<IUserService, UserService>();

var app = builder.Build();

app.UseSwagger();
app.UseAuthorization();
app.UseAuthentication();

app.MapPost("/login",
    (UserLogin user, IUserService service) => Login(user, service))
    .Accepts<UserLogin>("application/json")
    .Produces<string>();

app.MapPost("/create",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme,Roles ="Administrator")]
    (Movie movie, IMovieService service) => Create(movie, service))
    .Accepts<Movie>("application/json")
    .Produces<Movie>(statusCode:200, contentType: "application/json"); 

app.MapGet("/get",
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Standard, Administrator")]
(int id, IMovieService service) => Get(id, service))
    .Produces<Movie>();

app.MapGet("/list",
    ( IMovieService service) => GetAll(service))
     .Produces<List<Movie>>(statusCode:200, contentType: "application/json");

app.MapPut("/update",
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
(Movie newMovie, IMovieService service) => Update(newMovie, service))
     .Accepts<Movie>("application/json")
     .Produces<Movie>(statusCode: 200, contentType: "application/json");

app.MapDelete("/delete",
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
(int id, IMovieService service) => Delete(id, service));


IResult Login (UserLogin user, IUserService service) {  
        
    if(!string.IsNullOrEmpty(user.UserName) &&
        !string.IsNullOrEmpty(user.Password))
    {
        var loggerInUser = service.Get(user);
        if(loggerInUser is  null) Results.NotFound("User not found");

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, loggerInUser.UserName),
            new Claim(ClaimTypes.Email, loggerInUser.EmailAddress),
            new Claim(ClaimTypes.GivenName, loggerInUser.GivenName),
            new Claim(ClaimTypes.Surname, loggerInUser.Surname),
            new Claim(ClaimTypes.Role, loggerInUser.Role),
        };

        var token = new JwtSecurityToken(
            issuer: builder.Configuration["Jwt:Issuer"],
            audience: builder.Configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddDays(60),
            notBefore: DateTime.UtcNow,
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"])),
                SecurityAlgorithms.HmacSha256)
            );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

        return Results.Ok(tokenString);
    }

    return Results.BadRequest("Invalid user credentials");
}
IResult Create( Movie movie, IMovieService service)
{
     var result = service.Create(movie);
    return Results.Ok(result);
}
IResult Get(int id, IMovieService service)
{
    var movie = service.Get(id);
    if (movie is null) return Results.NotFound("Movie not found");
    return Results.Ok(movie);
}
IResult GetAll(IMovieService service)
{
    var movies = service.GetAll();
    if (movies is null) return Results.NotFound("Movies not found");
    return Results.Ok(movies); ;
}
IResult Update(Movie newMovie, IMovieService service)
{
    var updateMovie = service.Update(newMovie);
    if (updateMovie is null) return Results.NotFound("Movies not found");
    return Results.Ok(updateMovie);
}
IResult Delete(int id, IMovieService service)
{
    var result = service.Delete(id);
   if (!result) return Results.BadRequest("Something went wrong");
    return Results.Ok(result);
}

app.UseSwaggerUI();
app.Run();
