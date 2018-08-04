using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MSBLOC.Web.Models;
using Newtonsoft.Json;
using RestSharp;

namespace MSBLOC.Web.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        [Authorize]
        public IActionResult ListRepositories([FromServices] IOptions<Auth0ManagementApiOptions> optionsAccessor)
        {
            var options = optionsAccessor.Value;

            var client = new RestClient("https://msbuildlog-octokit-checker.auth0.com/oauth/token");
            var request = new RestRequest(Method.POST);
            request.AddHeader("content-type", "application/json");

            var requestParams = new
            {
                client_id = options.ClientId,
                client_secret = options.ClientSecret,
                audience = "https://msbuildlog-octokit-checker.auth0.com/api/v2/",
                grant_type = "client_credentials"
            };

            request.AddParameter("application/json", JsonConvert.SerializeObject(requestParams), ParameterType.RequestBody);
            var response = client.Execute(request);

            var responseContent = JsonConvert.DeserializeObject<dynamic>(response.Content);

            var accessToken = responseContent["access_token"];

            var userId = User.Claims.First(claim => claim.Type.Equals("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")).Value;

            client = new RestClient($"https://msbuildlog-octokit-checker.auth0.com/api/v2/users/{userId}");
            request = new RestRequest(Method.GET);
            request.AddHeader("authorization", $"Bearer {accessToken}");
            response = client.Execute(request);




            return View();
        }
    }
}
