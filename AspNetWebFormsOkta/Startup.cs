using IdentityModel.Client;

using Microsoft.AspNet.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;

using Owin;

using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;

[assembly: OwinStartup(typeof(AspNetWebFormsOkta.Startup))]

namespace AspNetWebFormsOkta
{
    public class Startup
    {
        // These values are stored in Web.config. Make sure you update them!
        private readonly string _clientId = ConfigurationManager.AppSettings["okta:ClientId"];

        private readonly string _redirectUri = ConfigurationManager.AppSettings["okta:RedirectUri"];
        private readonly string _authority = ConfigurationManager.AppSettings["okta:OrgUri"];
        private readonly string _clientSecret = ConfigurationManager.AppSettings["okta:ClientSecret"];

        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }

        public void ConfigureAuth(IAppBuilder app)
        {
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions());

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = _clientId,
                ClientSecret = _clientSecret,
                Authority = _authority,
                RedirectUri = _redirectUri,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                Scope = OpenIdConnectScope.OpenIdProfile,
                TokenValidationParameters = new TokenValidationParameters { NameClaimType = "name" },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = async n =>
                    {
                        // Exchange code for access and ID tokens
                        var tokenClient = new HttpClient();

                        var tokenResponse = await tokenClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
                        {
                            Address = $"{_authority}/v1/token",
                            ClientId = _clientId,
                            ClientSecret = _clientSecret,
                            Code = n.Code,
                            RedirectUri = _redirectUri,
                        });

                        if (tokenResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        var userInfoResponse = await tokenClient.GetUserInfoAsync(new UserInfoRequest
                        {
                            Address = $"{_authority}/v1/userinfo",
                            Token = tokenResponse.AccessToken
                        });

                        if (userInfoResponse.IsError)
                        {
                            throw new Exception(tokenResponse.Error);
                        }

                        var claims = new List<Claim>(userInfoResponse.Claims)
                        {
                            new Claim("id_token", tokenResponse.IdentityToken),
                            new Claim("access_token", tokenResponse.AccessToken)
                        };

                        foreach (var group in userInfoResponse.Claims.Where(x => x.Type == "groups"))
                        {
                            n.AuthenticationTicket.Identity.AddClaim(new Claim(ClaimTypes.Role, group.Value));
                        }
                        if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                        {
                            claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));
                        }
                        n.AuthenticationTicket.Identity.AddClaims(claims);

                    },
                },
            });
        }
    }
}