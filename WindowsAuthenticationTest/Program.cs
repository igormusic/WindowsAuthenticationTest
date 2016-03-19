using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityModel.Client;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;

namespace rbc.mt.WindowsAuthentication.Test
{
    class Program
    {
        static void Main(string[] args)
        {
            var handler = new HttpClientHandler
            {
                UseDefaultCredentials = true
            };

            var oauthClient = new OAuth2Client(
                new Uri("https://localhost:44350/token"),
                handler);

            var cert = GetCertificate("CN=sts");
            var key = new X509SecurityKey(cert);

            var result = oauthClient.RequestCustomGrantAsync("windows").Result as TokenResponse;

            JwtSecurityToken jwtToken;

            var claimsPrincipal = GetTokenFromString(result.AccessToken, "urn:idsrv3", "urn:windowsauthentication", key, 60, out jwtToken);


            Console.ForegroundColor = ConsoleColor.Green;

            Console.WriteLine("-----------------BEGIN JWT INFO -----------------");
            Console.WriteLine(GetJwtInfo(jwtToken));
            Console.WriteLine("------------------END JWT INFO ------------------");

            Console.ForegroundColor = ConsoleColor.Yellow;

            Console.WriteLine("---------BEGIN CLAIMS PRINCIPAL INFO ------------");
            Console.WriteLine(GetClaimsPrincpalInfo(claimsPrincipal));
            Console.WriteLine("----------END CLAIMS PRINCIPAL INFO -------------");

            Console.ResetColor();

            Console.ReadLine();
        }

       

        public static System.Security.Claims.ClaimsPrincipal GetTokenFromString(string tokenString, string audience, string issuer, SecurityKey key, int clockSkewInSeconds, out JwtSecurityToken jwtToken) {
            var jwtHandler = new JwtSecurityTokenHandler();

            var parms = new TokenValidationParameters();

            SecurityToken token;

            parms.ClockSkew = TimeSpan.FromSeconds(clockSkewInSeconds);

            parms.ValidAudience = audience;
            parms.ValidIssuer = issuer;
            parms.IssuerSigningKey = key;

            var claimsPrincipal = jwtHandler.ValidateToken(tokenString, parms, out token);

            jwtToken = token as JwtSecurityToken;

            return claimsPrincipal;
        }
       
        public static X509Certificate2 GetCertificate(string CNName) {
            X509Store store = new X509Store(StoreName.TrustedPeople,
                                                   StoreLocation.LocalMachine);
            X509Certificate2 cert= null;
            store.Open(OpenFlags.ReadOnly);

            var certs= store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, CNName, true);

            if (certs.Count > 0)
            {
                cert = certs[0];
            }
            store.Close();

            return cert;
        }

        public static string GetJwtInfo(JwtSecurityToken jwtToken) {
            var result = new StringBuilder();

            result.AppendFormat("Subject:{0}", jwtToken.Subject);
            result.AppendLine();

            result.AppendFormat("Issuer:{0}", jwtToken.Issuer);
            result.AppendLine();

            result.AppendFormat("ValidFrom:{0}", jwtToken.ValidFrom);
            result.AppendLine();

            result.AppendFormat("ValidTo:{0}", jwtToken.ValidTo);
            result.AppendLine();

            result.AppendFormat("Signature Algorithm:{0}", jwtToken.SignatureAlgorithm);
            result.AppendLine();

            result.AppendFormat("Signing Key:{0}", jwtToken.SigningKey);
            result.AppendLine();

            result.AppendLine();
            foreach (var audience in jwtToken.Audiences)
            {
                result.AppendFormat("Audience:{0}", audience);
                result.AppendLine();
            }
            foreach (var claim in jwtToken.Claims)
            {
                result.AppendFormat("Claim:{0}", claim);
                result.AppendLine();
            }

            return result.ToString();
        }

        public static string GetClaimsPrincpalInfo(ClaimsPrincipal claimsPrincipal)
        {
            var result = new StringBuilder();

            result.AppendFormat("Identity.Name:{0}", claimsPrincipal.Identity.Name);
            result.AppendLine();

            result.AppendFormat("Identity.AuthenticationType:{0}", claimsPrincipal.Identity.AuthenticationType);
            result.AppendLine();

            result.AppendFormat("Identity.IsAuthenticated:{0} ", claimsPrincipal.Identity.IsAuthenticated);
            result.AppendLine();

            foreach (var claim in claimsPrincipal.Claims)
            {
                result.AppendFormat("Claim:{0}", claim);
                result.AppendLine();
            }

            return result.ToString();
        }
    }
}
