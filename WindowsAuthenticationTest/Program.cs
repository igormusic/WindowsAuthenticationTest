using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityModel.Client;

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

            var result = oauthClient.RequestCustomGrantAsync("windows").Result;
        }
    }
}
