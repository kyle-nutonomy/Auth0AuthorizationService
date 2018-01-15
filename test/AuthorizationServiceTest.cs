using System;
using System.Collections.Generic;
using Xunit;
using Microsoft.AspNetCore.Authorization;
using Auth0Authorization;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace Auth0AuthorizationTest
{
    public class AuthorizationServiceTest
    {
        private readonly Dictionary<string,string[]> _scopePolicies;
        private readonly string _domainUrl;
        private readonly string _apiIdentifier;
        private readonly bool _isAuthRequired;

        private IAuthorizationService BuildAuthorizationService(Action<IServiceCollection> setupServices = null)
         {
             var services = new ServiceCollection();
             services.AddAuthorization();
             services.AddLogging();
             services.AddOptions();
             setupServices?.Invoke(services);
             return services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
        }

        public AuthorizationServiceTest()
        {
            var scopePolicies = new Dictionary<string,string[]>()
            {
                { "Read", new string[] { "read:messages" } },
                { "Write", new string[] { "write:messages" } },
                { "Admin", new string[] { "read:messages", "write:messages" } }
            };
            _scopePolicies = scopePolicies;
            _domainUrl = "http://test-domain.com";
            _apiIdentifier = "http://test-API.com";
            _isAuthRequired = true;
        }

        [Fact]
        public async Task AllowedPermissionIfUserContainsClaim()
        {
            var authorizationService = BuildAuthorizationService(services => 
            {
                services.AddAuthorizationService(_domainUrl, _apiIdentifier, _scopePolicies, _isAuthRequired);
            });

            var user = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new Claim[] { new Claim("scope", "read:messages", null, AuthorizationService.FormatUrl(_domainUrl)) }
                )
            );
            var allowed = await authorizationService.AuthorizeAsync(user, "Read");
            Assert.True(allowed.Succeeded);
        } 

        [Fact]
        public async Task DenyPermissionIfUserContainsWrongClaim()
        {
            var authorizationService = BuildAuthorizationService(services => 
            {
                services.AddAuthorizationService(_domainUrl, _apiIdentifier, _scopePolicies, _isAuthRequired);
            });

            var user = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new Claim[] { new Claim("scope", "read:messages", null, AuthorizationService.FormatUrl(_domainUrl)) }
                )
            );
            var writeAllowed = await authorizationService.AuthorizeAsync(user, "Write");
            Assert.False(writeAllowed.Succeeded);
            var adminAllowed = await authorizationService.AuthorizeAsync(user, "Admin");
            Assert.False(adminAllowed.Succeeded);
        }

        [Fact]
        public async Task AllowPermissionsIfUserSatisfiesMultipleScopes()
        {
            var authorizationService = BuildAuthorizationService(services => 
            {
                services.AddAuthorizationService(_domainUrl, _apiIdentifier, _scopePolicies, _isAuthRequired);
            });

            var user = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new Claim[] { 
                        new Claim("scope", "read:messages write:messages", null, AuthorizationService.FormatUrl(_domainUrl)),
                    }
                )
            );
            var writeAllowed = await authorizationService.AuthorizeAsync(user, "Write");
            Assert.True(writeAllowed.Succeeded);
            var readAllowed = await authorizationService.AuthorizeAsync(user, "Read");
            Assert.True(readAllowed.Succeeded);
            var adminAllowed = await authorizationService.AuthorizeAsync(user, "Admin");
            Assert.True(adminAllowed.Succeeded);
        }

        [Fact]
        public void ProperUrl()
        {
            var urlWithBackSlash = AuthorizationService.FormatUrl("http://test.com/");
            var urlWithout = AuthorizationService.FormatUrl("http://test.com");
            Assert.Equal("http://test.com/", urlWithBackSlash);
            Assert.Equal("http://test.com/", urlWithout);
        }
    }
}
