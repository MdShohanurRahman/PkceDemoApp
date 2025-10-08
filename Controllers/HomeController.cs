using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PkceDemoApp.Controllers
{
    public class HomeController : Controller
    {
        // Azure AD OAuth settings
        // web app registration details
        private static readonly string ClientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];
        private static readonly string ClientSecret = System.Configuration.ConfigurationManager.AppSettings["ClientSecret"];
        private static readonly string TenantId = System.Configuration.ConfigurationManager.AppSettings["TenantId"];
        private static readonly string RedirectUri = System.Configuration.ConfigurationManager.AppSettings["RedirectUri"];
        private const string Authority = "https://login.microsoftonline.com/" + TenantId;
        private const string Scope = "openid profile email";

        [AcceptVerbs(HttpVerbs.Get | HttpVerbs.Post)]
        public async Task<ActionResult> Index(string code, string error, string error_description, string state)
        {
            // Handle OAuth2 redirect back to root with code or error
            if (!string.IsNullOrEmpty(error))
            {
                ViewBag.Error = error;
                ViewBag.ErrorDescription = error_description;
                return View("Callback");
            }

            if (!string.IsNullOrEmpty(code))
            {
                // We have an auth code at root; exchange it for tokens (PKCE)
                string codeVerifier = TempData["code_verifier"] as string;
                if (string.IsNullOrEmpty(codeVerifier))
                {
                    // Fallback to state payload (for cases where session cookie isn't sent on cross-site POST)
                    codeVerifier = TryGetCodeVerifierFromState(state);
                }
                if (string.IsNullOrEmpty(codeVerifier))
                {
                    ViewBag.Error = "Code verifier missing from session.";
                    return View("Callback");
                }

                var exchangeError = await ExchangeCodeForTokensAsync(code, codeVerifier);
                if (exchangeError != null)
                {
                    ViewBag.Error = exchangeError;
                    return View("Callback");
                }
                // Clear code from URL
                return RedirectToAction("Index");
            }

            // No code: show appropriate page based on auth status
            if (Session["id_token"] == null)
            {
                return View("Login");
            }
            ViewBag.User = Session["user_name"];
            return View("Home");
        }

        public ActionResult Login()
        {
            // Generate PKCE code verifier and challenge
            string codeVerifier = GenerateCodeVerifier();
            string codeChallenge = GenerateCodeChallenge(codeVerifier);
            TempData["code_verifier"] = codeVerifier;

            // Build state that carries the verifier as a fallback in case session cookie isn't available
            string state = BuildStateFromCodeVerifier(codeVerifier);

            // Build authorization URL
            string authUrl = BuildAuthorizeUrl(codeChallenge, state);
            return Redirect(authUrl);
        }
        
        public ActionResult Logout()
        {
            Session.Clear();
            return RedirectToAction("Index");
        }

        // PKCE helpers
        private static string GenerateCodeVerifier()
        {
            var bytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }
            return Base64UrlEncodeNoPadding(bytes);
        }
        private static string GenerateCodeChallenge(string codeVerifier)
        {
            using (var sha256 = SHA256.Create())
            {
                var challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                return Base64UrlEncodeNoPadding(challengeBytes);
            }
        }
        private static string Base64UrlEncodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);
            base64 = base64.Replace("+", "-").Replace("/", "_").Replace("=", "");
            return base64;
        }

        private static string Base64UrlDecodeToString(string input)
        {
            if (string.IsNullOrEmpty(input)) return null;
            string s = input.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            var bytes = Convert.FromBase64String(s);
            return Encoding.UTF8.GetString(bytes);
        }

        private static string BuildStateFromCodeVerifier(string codeVerifier)
        {
            // Very small JSON payload carrying the code_verifier and timestamp
            var json = "{\"cv\":\"" + codeVerifier + "\",\"ts\":" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() + "}";
            return Base64UrlEncodeNoPadding(Encoding.UTF8.GetBytes(json));
        }

        private static string TryGetCodeVerifierFromState(string state)
        {
            try
            {
                var json = Base64UrlDecodeToString(state);
                if (string.IsNullOrEmpty(json)) return null;
                dynamic obj = System.Web.Helpers.Json.Decode(json);
                return obj.cv;
            }
            catch
            {
                return null;
            }
        }

        // Functional-ish helpers to reduce duplication
        private string BuildAuthorizeUrl(string codeChallenge, string state)
        {
            var queryParams = new Dictionary<string, string>
            {
                { "client_id", ClientId },
                { "response_type", "code" },
                { "redirect_uri", RedirectUri },
                { "response_mode", "form_post" },
                { "scope", Scope },
                { "code_challenge", codeChallenge },
                { "code_challenge_method", "S256" },
                { "prompt", "select_account" },
                { "state", state }
            };
            var query = string.Join("&", queryParams.Select(kvp => kvp.Key + "=" + HttpUtility.UrlEncode(kvp.Value)));
            return Authority + "/oauth2/v2.0/authorize?" + query;
        }

        private async Task<string> ExchangeCodeForTokensAsync(string code, string codeVerifier)
        {
            try
            {
                using (var client = new System.Net.Http.HttpClient())
                {
                    var values = new Dictionary<string, string>
                    {
                        { "client_id", ClientId },
                        { "client_secret", ClientSecret },
                        { "scope", Scope },
                        { "code", code },
                        { "redirect_uri", RedirectUri },
                        { "grant_type", "authorization_code" },
                        { "code_verifier", codeVerifier }
                    };
                    var content = new System.Net.Http.FormUrlEncodedContent(values);
                    var response = await client.PostAsync($"https://login.microsoftonline.com/{TenantId}/oauth2/v2.0/token", content);
                    var responseString = await response.Content.ReadAsStringAsync();
                    if (!response.IsSuccessStatusCode)
                    {
                        return $"Token endpoint error: {response.StatusCode} {responseString}";
                    }
                    dynamic json = System.Web.Helpers.Json.Decode(responseString);
                    Session["access_token"] = json.access_token;
                    Session["id_token"] = json.id_token;
                    Session["refresh_token"] = json.refresh_token;
                    var idToken = json.id_token as string;
                    var userName = TryGetUserNameFromIdToken(idToken);
                    if (!string.IsNullOrEmpty(userName))
                    {
                        Session["user_name"] = userName;
                    }
                }
                return null;
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        private static string TryGetUserNameFromIdToken(string idToken)
        {
            if (string.IsNullOrEmpty(idToken)) return null;
            var parts = idToken.Split('.');
            if (parts.Length != 3) return null;
            var payload = parts[1];
            var pad = 4 - payload.Length % 4;
            if (pad < 4) payload += new string('=', pad);
            var bytes = Convert.FromBase64String(payload.Replace('-', '+').Replace('_', '/'));
            var payloadJson = Encoding.UTF8.GetString(bytes);
            dynamic payloadObj = System.Web.Helpers.Json.Decode(payloadJson);
            return payloadObj.name ?? payloadObj.preferred_username ?? "User";
        }
    }
}