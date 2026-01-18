using System.Security.Claims;
using Adopet.Api.Controllers;
using Adopet.Api.Dtos;
using Adopet.Api.Options;
using Adopet.Application.Interfaces;
using Adopet.Application.Services;
using Adopet.Domain.Interfaces;
using Adopet.Domain.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moq;

namespace Adopet.Identity.Tests.Api.Controllers;

public class AuthControllerTests
{
    private readonly Mock<IUserService<ApplicationUser>> _userServiceMock = new();
    private readonly Mock<IRefreshTokenRepository> _refreshTokenRepositoryMock = new();
    
    private AuthController _sut;

    public AuthControllerTests()
    {
        var jwtOptions = Options.Create(new JwtOptions
        {
            Key = "this_is_a_32_character_secret_key",
            Issuer = "adopet-identity",
            Audiences = ["adopet-api"],
            UserExpires = TimeSpan.FromMinutes(15),
            ServiceExpires = TimeSpan.FromMinutes(15),
        });
        
        var refreshTokenOptions = Options.Create(new RefreshTokenOptions
        {
            Expires = TimeSpan.FromDays(7)
        });
        
        _sut = new AuthController(
            _userServiceMock.Object, 
            new JwtGenerator(jwtOptions), 
            _refreshTokenRepositoryMock.Object,
            refreshTokenOptions);
    }
    
    #region RegisterAsync

    [Fact]
    public async Task RegisterAsync_Success()
    {
        // Arrange
        const string email = "email@test.com";
        const string password = "test_password";

        _userServiceMock
            .Setup(um =>
                um.CreateAsync(It.Is<ApplicationUser>(au => au.UserName == email && au.Email == email), password))
            .ReturnsAsync(IdentityResult.Success);

        // Act
        var result = await _sut.RegisterAsync(new RegisterRequest(email, password));

        // Assert
        Assert.IsType<OkResult>(result);
    }

    [Fact]
    public async Task RegisterAsync_Failure()
    {
        // Arrange
        const string email = "email@test.com";
        const string password = "test_password";

        const string errorCode = "error.code";
        const string errorDescription = "error description";

        _userServiceMock
            .Setup(um =>
                um.CreateAsync(It.Is<ApplicationUser>(au => au.UserName == email && au.Email == email), password))
            .ReturnsAsync(IdentityResult.Failed(new IdentityError
            {
                Code = "error.code",
                Description = "error description"
            }));

        // Act
        var result = await _sut.RegisterAsync(new RegisterRequest(email, password));

        // Assert
        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        var errors = Assert.IsType<List<IdentityError>>(badRequestResult.Value);
        Assert.Single(errors);
        Assert.Equal(errorCode, errors[0].Code);
        Assert.Equal(errorDescription, errors[0].Description);
    }
    
    #endregion RegisterAsync
    
    #region LoginAsync
    
    [Fact]
    public async Task LoginAsync_Success()
    {
        // Arrange
        const string email = "email@test.com";
        const string password = "test_password";
        const string refreshToken = "refresh-token";

        var userId = Guid.NewGuid();
        
        var applicationUser = new ApplicationUser
        {
            Id = userId,
            Email = email
        };

        _userServiceMock
            .Setup(um => um.FindByEmailAsync(email))
            .ReturnsAsync(applicationUser);
        
        _userServiceMock
            .Setup(um => um.CheckPasswordAsync(applicationUser, password))
            .ReturnsAsync(true);

        _refreshTokenRepositoryMock
            .Setup(rtp => rtp.CreateAsync(userId, It.IsAny<DateTime>()))
            .ReturnsAsync(refreshToken);

        // Act
        var result = await _sut.LoginAsync(new LoginRequest(email, password));

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<TokenResponse>(okResult.Value);
        Assert.NotNull(response.AccessToken);
        Assert.NotNull(response.RefreshToken);
        Assert.Equal(refreshToken, response.RefreshToken);
    }

    [Fact]
    public async Task LoginAsync_EmailDoesNotExist_ReturnUnauthorized()
    {
        // Arrange
        const string email = "email@test.com";
        const string password = "test_password";
        
        var userId = Guid.NewGuid();

        var applicationUser = new ApplicationUser
        {
            Id = userId,
            Email = email
        };

        _userServiceMock
            .Setup(um => um.FindByEmailAsync(email))
            .ReturnsAsync(applicationUser);
        
        _userServiceMock
            .Setup(um => um.CheckPasswordAsync(applicationUser, password))
            .ReturnsAsync(false);
        
        // Act
        var result = await _sut.LoginAsync(new LoginRequest(email, password));

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }

    [Fact]
    public async Task LoginAsync_PasswordIsInvalid_ReturnUnauthorized()
    {
        // Arrange
        const string email = "email@test.com";
        const string password = "test_password";

        _userServiceMock
            .Setup(um => um.FindByEmailAsync(email))
            .ReturnsAsync((ApplicationUser?)null);
        
        // Act
        var result = await _sut.LoginAsync(new LoginRequest(email, password));

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }
    
    #endregion LoginAsync
    
    #region RefreshAsync
    
    [Fact]
    public async Task RefreshAsync_Success()
    {
        // Arrange        
        const string email = "email@test.com";
        const string existingRefreshToken = "existing-refresh-token";
        const string newRefreshToken = "new-refresh-token";
        var userId = Guid.NewGuid();
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        };

        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"))
            }
        };
        
        var applicationUser = new ApplicationUser
        {
            Id = userId,
            Email = email
        };

        _userServiceMock
            .Setup(um => um.FindByIdAsync(userId.ToString()))
            .ReturnsAsync(applicationUser);
        
        _refreshTokenRepositoryMock
            .Setup(rtp => rtp.RefreshAsync(userId, existingRefreshToken, It.IsAny<DateTime>()))
            .ReturnsAsync(newRefreshToken);

        // Act
        var result = await _sut.RefreshAsync(new RefreshRequest(existingRefreshToken));

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<TokenResponse>(okResult.Value);
        Assert.NotNull(response.AccessToken);
        Assert.NotNull(response.RefreshToken);
        Assert.Equal(newRefreshToken, response.RefreshToken);
    }
    
    [Fact]
    public async Task RefreshAsync_NameIdentifierClaimDoesNotExist_ReturnUnauthorized()
    {
        // Arrange        
        const string refreshToken = "refresh-token";
        
        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity())
            }
        };

        // Act
        var result = await _sut.RefreshAsync(new RefreshRequest(refreshToken));

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }
    
    [Fact]
    public async Task RefreshAsync_UserDoesNotExist_ReturnUnauthorized()
    {
        // Arrange        
        const string refreshToken = "refresh-token";
        var userId = Guid.NewGuid();
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        };

        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"))
            }
        };
        
        _userServiceMock
            .Setup(um => um.FindByIdAsync(userId.ToString()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _sut.RefreshAsync(new RefreshRequest(refreshToken));

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }
    
    [Fact]
    public async Task RefreshAsync_RefreshTokenIsNull_ReturnUnauthorized()
    {
        // Arrange        
        const string email = "email@test.com";
        const string existingRefreshToken = "existing-refresh-token";
        var userId = Guid.NewGuid();
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        };

        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"))
            }
        };
        
        var applicationUser = new ApplicationUser
        {
            Id = userId,
            Email = email
        };

        _userServiceMock
            .Setup(um => um.FindByIdAsync(userId.ToString()))
            .ReturnsAsync(applicationUser);
        
        _refreshTokenRepositoryMock
            .Setup(rtp => rtp.RefreshAsync(userId, existingRefreshToken, It.IsAny<DateTime>()))
            .ReturnsAsync((string?)null);

        // Act
        var result = await _sut.RefreshAsync(new RefreshRequest(existingRefreshToken));

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }

    #endregion RefreshAsync
    
    #region LogoutAsync
    
    [Fact]
    public async Task LogoutAsync_Success()
    {
        // Arrange        
        const string refreshToken = "existing-refresh-token";

        _refreshTokenRepositoryMock
            .Setup(rtp => rtp.RevokeAsync(refreshToken));

        // Act
        var result = await _sut.LogoutAsync(new LogoutRequest(refreshToken));

        // Assert
        Assert.IsType<OkResult>(result);
    }
    
    #endregion LogoutAsync
    
    #region LogoutAllAsync
    
    [Fact]
    public async Task LogoutAllAsync_Success()
    {
        // Arrange        
        const string email = "email@test.com";
        var userId = Guid.NewGuid();
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        };

        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"))
            }
        };
        
        _userServiceMock
            .Setup(um => um.FindByIdAsync(userId.ToString()))
            .ReturnsAsync(new ApplicationUser
            {
                Id = userId,
                Email = email
            });

        _refreshTokenRepositoryMock
            .Setup(rtp => rtp.RevokeAllAsync(userId));

        // Act
        var result = await _sut.LogoutAllAsync();

        // Assert
        Assert.IsType<OkResult>(result);
    }
    
    [Fact]
    public async Task LogoutAllAsync_NameIdentifierClaimDoesNotExist_ReturnUnauthorized()
    {
        // Arrange
        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity())
            }
        };
        
        // Act
        var result = await _sut.LogoutAllAsync();

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }
    
    [Fact]
    public async Task LogoutAllAsync_UserDoesNotExist_ReturnUnauthorized()
    {
        // Arrange        
        var userId = Guid.NewGuid();
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
        };

        _sut.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(claims, "TestAuth"))
            }
        };
        
        _userServiceMock
            .Setup(um => um.FindByIdAsync(userId.ToString()))
            .ReturnsAsync((ApplicationUser?)null);

        // Act
        var result = await _sut.LogoutAllAsync();

        // Assert
        Assert.IsType<UnauthorizedResult>(result);
    }
    
    #endregion LogoutAllAsync
}