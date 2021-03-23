using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Okta.AspNetCore;
using System;
using AspNetCore.Authentication.Okta;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class ConfigurationExtensions
    {
        public static IMvcBuilder AddMvcWithAuthorizeFilter(this IServiceCollection services, bool addAuthorizeFilter = true)
        {
            if (services == null)
                throw new ArgumentNullException(nameof(services));

            return services.AddMvc(o =>
            {
                if (addAuthorizeFilter)
                {
                    var policy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
                    o.Filters.Add(new AuthorizeFilter(policy));
                }
            });
        }

        public static IServiceCollection AddOktaMvcAuthentication(this IServiceCollection services, OktaConfig oktaConfig)
        {
            if (services == null)
                throw new ArgumentNullException(nameof(services));

            if (oktaConfig.ClientIsPopulated())
            {
                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OktaDefaults.MvcAuthenticationScheme;
                })
                .AddCookie()
                .AddOktaMvc(new OktaMvcOptions
                {
                    OktaDomain = oktaConfig.Domain,
                    ClientId = oktaConfig.ClientId,
                    ClientSecret = oktaConfig.ClientSecret,
                    AuthorizationServerId = oktaConfig.AuthorizationServerId ?? ""
                });
            }

            return services;
        }

        public static bool DomainIsPopulated(this OktaConfig oktaConfig)
        {
            return !string.IsNullOrWhiteSpace(oktaConfig?.Domain);
        }

        public static bool ClientIsPopulated(this OktaConfig oktaConfig)
        {
            return oktaConfig != null
                && !string.IsNullOrWhiteSpace(oktaConfig.Domain)
                && !string.IsNullOrWhiteSpace(oktaConfig.ClientId)
                && !string.IsNullOrWhiteSpace(oktaConfig.ClientSecret);
        }
    }
}
