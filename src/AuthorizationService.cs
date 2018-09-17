using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging;

namespace Auth0Authorization
{
    public static class AuthorizationService
    {   
        public static void AddAuthorizationService(this IServiceCollection services, string authorityDomain, string apiIdentifier, Dictionary<string, string[]> scopePolicies, bool isAuthRequired = false)
        {
            var authDomainUrl = FormatUrl(authorityDomain);
            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
                {
                    options.Authority = authDomainUrl;
                    options.Audience = apiIdentifier;
                });
            services.AddAuthorization(options =>
            {
                if (isAuthRequired)
                {
                    foreach (var policyPermissions in scopePolicies)
                    {
                        options.AddPolicy(policyPermissions.Key,
                            policy => policy.Requirements.Add(new IntersectionPermissions(policyPermissions.Value,
                            authDomainUrl))
                        );
                    }
                }
                else
                {
                    // Choose which policy to passthrough when authentication is not required.
                    options.DefaultPolicy = new AuthorizationPolicyBuilder().RequireAssertion(_ => true).Build();
                    foreach (var policyPermissions in scopePolicies)
                    {
                        options.AddPolicy(policyPermissions.Key, options.DefaultPolicy);

                    }
                }
            });
        }

        private class IntersectionPermissions : AuthorizationHandler<IntersectionPermissions>, IAuthorizationRequirement
        {
            private readonly string _issuer;
            private readonly IEnumerable<string> _policyScopes;
            private readonly ILogger<IAuthorizationHandler> _logger;

            // field which contains permissions in jwt
            private const string PermissionsField = "scope";

            public IntersectionPermissions(IEnumerable<string> policyScopes, string issuer)
            {
                _policyScopes = policyScopes;
                _issuer = issuer;
                _logger = new LoggerFactory().AddConsole().CreateLogger<IAuthorizationHandler>();
            }

            protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IntersectionPermissions requirement)
            {
                _logger.LogInformation(context.User.FindFirstValue(ClaimTypes.NameIdentifier));
                if (!context.User.HasClaim(c => c.Type == PermissionsField && c.Issuer == _issuer))
                {   
                    return Task.CompletedTask;
                }

                // Split the scopes string into an array
                var userScopes = context.User.FindFirst(c => c.Type == PermissionsField && c.Issuer == _issuer).Value.Split(' ');

                // Succeed if the user permissions is superset of this policy
                if (!_policyScopes.Except(userScopes).Any())
                {
                    context.Succeed(requirement);
                }

                return Task.CompletedTask;
            }
        }

        public static string FormatUrl(string url)
        {
            return url + (url[url.Length - 1] == '/' ? "" : "/");
        }
    }
}
