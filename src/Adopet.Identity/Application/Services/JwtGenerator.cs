using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Adopet.Api.Options;
using Adopet.Domain.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Adopet.Application.Services;

public class JwtGenerator(IOptions<JwtOptions> jwtOptions)
{
    public string Generate(ApplicationUser user, string? audience)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email,
                user.Email ?? throw new InvalidOperationException("Application User Email is null."))
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Value.Key));

        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var expires = user.IsService ? jwtOptions.Value.ServiceExpires : jwtOptions.Value.UserExpires;

        var token = new JwtSecurityToken(
            issuer: jwtOptions.Value.Issuer,
            audience: audience ?? jwtOptions.Value.Audiences[0],
            claims: claims,
            expires: DateTime.UtcNow + expires,
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}