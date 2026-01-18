using System.Security.Claims;
using Adopet.Api.Dtos;
using Adopet.Api.Options;
using Adopet.Application.Services;
using Adopet.Domain.Interfaces;
using Adopet.Domain.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Adopet.Api.Controllers;

[ApiController]
[Authorize]
[Route("auth")]
public class AuthController(
    UserManager<ApplicationUser> userManager, 
    JwtGenerator jwtGenerator,
    IRefreshTokenRepository refreshTokenRepository,
    IOptions<RefreshTokenOptions> refreshTokenOptions) : ControllerBase
{
    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var user = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            UserName = request.Email,
            Email = request.Email
        };
        
        var result = await userManager.CreateAsync(user, request.Password);
        
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok();
    }
    
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request, CancellationToken cancellationToken = default)
    {
        var user = await userManager.FindByEmailAsync(request.Email);
        if (user == null)
            return Unauthorized();

        var valid = await userManager.CheckPasswordAsync(user, request.Password);
        if (!valid)
            return Unauthorized();

        var accessToken = jwtGenerator.Generate(user, request.Audience);
        var refreshToken = await refreshTokenRepository.CreateAsync(
            user.Id, 
            DateTime.UtcNow + refreshTokenOptions.Value.Expires, 
            cancellationToken);

        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }
    
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(RefreshRequest request, CancellationToken cancellationToken = default)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();
        
        var user = await userManager.FindByIdAsync(userId);
        if (user == null)
            return Unauthorized();
        
        var audience = User.FindFirst(JwtRegisteredClaimNames.Aud)?.Value;
        
        var refreshToken = await refreshTokenRepository.RefreshAsync(
            user.Id,
            request.RefreshToken, 
            DateTime.UtcNow + refreshTokenOptions.Value.Expires, 
            cancellationToken);
        
        if (refreshToken == null)
            return Unauthorized();
        
        var accessToken = jwtGenerator.Generate(user, audience);
            
        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }
    
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(LogoutRequest request, CancellationToken cancellationToken = default)
    {
        await refreshTokenRepository.RevokeAsync(request.RefreshToken, cancellationToken);
        return Ok();
    }
    
    [HttpPost("logout-all")]
    public async Task<IActionResult> LogoutAll(CancellationToken cancellationToken = default)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null)
            return Unauthorized();
        
        var user = await userManager.FindByIdAsync(userId);
        if (user == null)
            return Unauthorized();
        
        await refreshTokenRepository.RevokeAllAsync(user.Id, cancellationToken);
        return Ok();
    }
}