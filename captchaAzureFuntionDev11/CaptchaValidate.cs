using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net.Http;
using System.Text;
using System.Net;
using System.Collections.Generic;

namespace captchaAzureFuntionDev11
{
    public static class CaptchaValidate
    {
        [FunctionName("CaptchaValidate")]
        public static async Task<object> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger captchaFuntion processed a request.");

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogInformation("Request body: " + requestBody);

            // Check HTTP basic authorization
            if (!Authorize(req, log))
            {
                log.LogWarning("HTTP basic authentication validation failed.");
                var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(new ResponseObject()
                    {
                        action = "ShowBlockPage",
                        userMessage = "La verificación de Captcha falló debido a una autenticación no válida. Comuníquese con el administrador para solucionar este problema.",
                        code = "B2C004",
                        status = 400,
                        version = "1.0.0"
                    }), Encoding.UTF8, "application/json")
                };
                string responseBody = await response.Content.ReadAsStringAsync();
                log.LogInformation("Response: " + responseBody);
                   return response;
                 //return new OkObjectResult(response);
            }

            string ID_Aplicacion = System.Environment.GetEnvironmentVariable("B2C_EXTENSIONS_APP_ID", EnvironmentVariableTarget.Process);
            // string id_tokek = "extension_" + ID_Aplicacion + "_CaptchaUserResponseToken";
            string id_tokek = "extension_CaptchaUserResponseToken";
            string secret_key= System.Environment.GetEnvironmentVariable("CAPTCHA_SECRET_KEY", EnvironmentVariableTarget.Process);


            dynamic data = JsonConvert.DeserializeObject(requestBody);

            string extension_CaptchaUserResponseToken = data?.extension_CaptchaUserResponseToken; //extension app-id
            log.LogInformation("app id: " + ID_Aplicacion);
            log.LogInformation("token: " + extension_CaptchaUserResponseToken);
            log.LogInformation("secret_key: " + secret_key);

            bool verified_captcha = !string.IsNullOrEmpty(extension_CaptchaUserResponseToken);

            using (var client = new HttpClient())
            {
                Dictionary<string, string> dictionary = new Dictionary<string, string>();
                dictionary.Add("secret", secret_key);
                dictionary.Add("response", extension_CaptchaUserResponseToken);
                var formContent = new FormUrlEncodedContent(dictionary);

                var result = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", formContent);
                string resultContent = await result.Content.ReadAsStringAsync();
                log.LogInformation("Response from captcha service: " + resultContent);
                dynamic data_captcha = JsonConvert.DeserializeObject(resultContent);
                verified_captcha = data_captcha.success;
            }

            if (verified_captcha)
            {
                var response = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(new ResponseObjectNoMessage()
                    {
                        action = "Continue",
                        extension_CaptchaUserResponseToken = ""
                    }), Encoding.UTF8, "application/json")
                };
                string responseBody = await response.Content.ReadAsStringAsync();
                log.LogInformation("Response: " + responseBody);
                //return new OkObjectResult(response);
                return response;
            }
            else
            {
                var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(new ResponseObject()
                    {
                        action = "ValidationError",
                        userMessage = "Captcha no válida o captcha expiró",
                        code = "B2C003",
                        status = 400,
                        version = "1.0.0"
                    }), Encoding.UTF8, "application/json")
                };
                string responseBody = await response.Content.ReadAsStringAsync();
                log.LogInformation("Response: " + responseBody);
                return response;
                //return new OkObjectResult(response);
            }
        }




        private static bool Authorize(HttpRequest req, ILogger log)
        {
            // Get the environment's credentials 
            string username = System.Environment.GetEnvironmentVariable("BASIC_AUTH_USERNAME", EnvironmentVariableTarget.Process);
            string password = System.Environment.GetEnvironmentVariable("BASIC_AUTH_PASSWORD", EnvironmentVariableTarget.Process);

            // Returns authorized if the username is empty or not exists.
            if (string.IsNullOrEmpty(username))
            {
                log.LogInformation("HTTP basic authentication is not set.");
                return true;
            }

            // Check if the HTTP Authorization header exist
            if (!req.Headers.ContainsKey("Authorization"))
            {
                log.LogWarning("Missing HTTP basic authentication header.");
                return false;
            }

            // Read the authorization header
            var auth = req.Headers["Authorization"].ToString();

            // Ensure the type of the authorization header id `Basic`
            if (!auth.StartsWith("Basic "))
            {
                log.LogWarning("HTTP basic authentication header must start with 'Basic '.");
                return false;
            }

            // Get the the HTTP basic authorization credentials
            var cred = System.Text.UTF8Encoding.UTF8.GetString(Convert.FromBase64String(auth.Substring(6))).Split(':');

            // Evaluate the credentials and return the result
            return (cred[0] == username && cred[1] == password);
        }



        public class ResponseObject
        {
            public string action { get; set; }
            public string userMessage { get; set; }
            public string code { get; set; }
            public string version { get; set; }
            public int status { get; set; }
        }

        private class ResponseObjectNoMessage
        {
            public string action { get; set; }
            public string extension_CaptchaUserResponseToken { get; set; }
        }
    }
}
