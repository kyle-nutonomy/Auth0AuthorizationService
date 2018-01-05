using System;
using System.Collections.Generic;
using Xunit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Auth0Authorization;
using System.Security.Claims;
using System.Threading.Tasks;
using Moq;

namespace Auth0AuthorizationTest
{
    public class AuthorizationServiceTest
    {
        private readonly AuthorizationService _authorizationService;

        public AuthorizationServiceTest()
        {
            var scopePolicies = new Dictionary<string,string[]>()
            {
                { "Read", new string[] { "read:messages" } },
                { "Write", new string[] { "write:messages" } },
                { "Admin", new string[] { "read:messages", "write:messages" } }
            };
            _authorizationService = new AuthorizationService(scopePolicies);
        }

        [Fact]
        public async Task AllowedUser()
        {
            _authorizationService.AddAuthorizationPolicies(,"",false);
            var user = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new Claim[] { new Claim("Read", "read:messages") }
                )
            );
            var allowed = await authService.AuthorizeAsync(user, "Basic");
            Assert.True(allowed);
        }
    }
}
