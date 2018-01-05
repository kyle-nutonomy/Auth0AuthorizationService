using System.Collections.Generic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;
using System.Linq;

namespace Auth0Authorization
{
    public class AuthorizationService
    {
        private Dictionary<string, string[]> _scopePolicies;
        public AuthorizationService(Dictionary<string,string[]> scopePolicies)
        {
            _scopePolicies = scopePolicies;
        }
        public void AddAuthorizationPolicies(IServiceCollection services, string authorityDomain, bool isAuthRequired = false)
        {
            services.AddAuthorization(options =>
            {
                var authDomainUrl = authorityDomain + ((authorityDomain[authorityDomain.Length-1]=='/') ? "" : "/");
                if (isAuthRequired)
                {   
                    foreach(KeyValuePair<string,string[]> policyPermissions in _scopePolicies)
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
                    foreach (KeyValuePair<string, string[]> policyPermissions in _scopePolicies)
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
            // field which contains permissions in jwt
            private const string PermissionsField = "scope";

            public IntersectionPermissions(IEnumerable<string> policyScopes, string issuer)
            {
                _policyScopes = policyScopes;
                _issuer = issuer;
            }

            protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, IntersectionPermissions requirement)
            {
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
    }
}
