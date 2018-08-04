using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using GitHubJwt;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MSBLOC.Core.Interfaces;
using MSBLOC.Core.Services;
using MSBLOC.Web.Attributes;
using MSBLOC.Web.Interfaces;
using MSBLOC.Web.Models;
using MSBLOC.Web.Services;
using MSBLOC.Web.Util;
using Swashbuckle.AspNetCore.Swagger;

namespace MSBLOC.Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            // Add authentication services
            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCookie()
                .AddOpenIdConnect("Auth0", options =>
                {
                    // Set the authority to your Auth0 domain
                    options.Authority = $"https://{Configuration["Auth0:Domain"]}";

                    // Configure the Auth0 Client ID and Client Secret
                    options.ClientId = Configuration["Auth0:ClientId"];
                    options.ClientSecret = Configuration["Auth0:ClientSecret"];

                    // Set response type to code
                    options.ResponseType = "code";

                    // Configure the scope
                    options.Scope.Clear();
                    options.Scope.Add("openid");

                    // Set the callback path, so Auth0 will call back to http://{domain:port}/signin-auth0
                    // Also ensure that you have added the URL as an Allowed Callback URL in your Auth0 dashboard
                    options.CallbackPath = new PathString("/signin-auth0");

                    // Configure the Claims Issuer to be Auth0
                    options.ClaimsIssuer = "Auth0";

                    options.Events = new OpenIdConnectEvents
                    {
                        /*
                        OnRedirectToIdentityProvider = context =>
                        {
                            context.ProtocolMessage.SetParameter("audience", "{YOUR_API_IDENTIFIER}");

                            return Task.FromResult(0);
                        },
                        */
                        // handle the logout redirection
                        OnRedirectToIdentityProviderForSignOut = (context) =>
                        {
                            var logoutUri = $"https://{Configuration["Auth0:Domain"]}/v2/logout?client_id={Configuration["Auth0:ClientId"]}";

                            var postLogoutUri = context.Properties.RedirectUri;
                            if (!string.IsNullOrEmpty(postLogoutUri))
                            {
                                if (postLogoutUri.StartsWith("/"))
                                {
                                    // transform to absolute
                                    var request = context.Request;
                                    postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase + postLogoutUri;
                                }

                                logoutUri += $"&returnTo={Uri.EscapeDataString(postLogoutUri)}";
                            }

                            context.Response.Redirect(logoutUri);
                            context.HandleResponse();

                            return Task.CompletedTask;
                        }
                    };
                }); 

            services.AddMvc().AddJsonOptions(options =>
            {
                options.SerializerSettings.Converters.Add(new OctokitStringEnumConverter());
            });

            services.Configure<EnvOptions>(Configuration);

            services.AddSingleton<IPrivateKeySource, OptionsPrivateKeySource>();
            services.AddSingleton<Func<string, Task<ICheckRunSubmitter>>>(s => async repoOwner =>
            {
                var gitHubAppId = s.GetService<IOptions<EnvOptions>>().Value.GitHubAppId;
                var privateKeySource = s.GetService<IPrivateKeySource>();
                var gitHubTokenGenerator = new TokenGenerator(gitHubAppId, privateKeySource, s.GetService<ILogger<TokenGenerator>>());

                var gitHubClientFactory = new GitHubClientFactory(gitHubTokenGenerator);
                var gitHubClient = await gitHubClientFactory.CreateClientForLogin(repoOwner);

                return new CheckRunSubmitter(gitHubClient.Check.Run, s.GetService<ILogger<CheckRunSubmitter>>());
            });

            services.AddScoped<ITempFileService, LocalTempFileService>();
            services.AddScoped<IBinaryLogProcessor, BinaryLogProcessor>();

            services.AddTransient<IMSBLOCService, MSBLOCService>();

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("0.0.1", new Info { Title = "MSBLOC Web API", Version = "0.0.1" });
                c.OperationFilter<MultiPartFormBindingAttribute.MultiPartFormBindingFilter>();
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseSwagger(c =>
            {
                c.RouteTemplate = "docs/{documentName}/swagger.json";

                //Make routes lower case (Controller names for example)
                c.PreSerializeFilters.Add((document, request) =>
                {
                    document.Paths = document.Paths.ToDictionary(item => item.Key.ToLowerInvariant(), item => item.Value);
                });
            });

            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/docs/0.0.1/swagger.json", "MSBLOC Web API");
                c.RoutePrefix = "docs";
            });

            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
