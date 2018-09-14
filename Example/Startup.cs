using System.Collections.Generic;
using System.Linq;
using Auth0Authorization;
using DriveLogs;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Swashbuckle.AspNetCore.Swagger;

namespace DriveLogExtractions
{
    public class Startup
    {
        private IConfiguration Configuration { get; }

        private const string AuthorityDomain = "";
        private const string ApiIdentifier = "";
        
        public Startup(IConfiguration configuration, IHostingEnvironment environment)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new Info {Title = "Example API", Version = "v1"});
                c.AddSecurityDefinition("Bearer", new ApiKeyScheme
                {
                    In = "header", Name = "Authorization", Type = "apiKey"
                });
                c.AddSecurityRequirement(
                    new Dictionary<string, IEnumerable<string>> { { "Bearer", Enumerable.Empty<string>() } });

            });
            // configure auth for DriveLogs
            services.AddAuthorizationService(
                AuthorityDomain,
                ApiIdentifier,
                AuthorizationPolicies.ScopePolicies,
                true);
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            app.UseSwagger();
            app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", "Example API V1"); });
            app.UseAuthentication();
            app.UseMvc();
        }
    }
}