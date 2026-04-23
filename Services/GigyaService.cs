using Gigya.Socialize.SDK;
using log4net;
using Newtonsoft.Json;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace GigyaJWTRestPOC.Services
{
    public class JWTPublicKey
    {
        public string kty { get; set; }
        public string n { get; set; }
        public string e { get; set; }
        public string alg { get; set; }
        public string use { get; set; }
    }
    public class CertificateStatus
    {
        public string Thumbprint { get; set; }
        public bool Found { get; set; }
        public bool HasPrivateKey { get; set; }
        public bool CanSign { get; set; }
        public int? KeySize { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public string Message { get; set; }
    }
    public class GigyaService
    {

        private static readonly ILog log = LogManager.GetLogger(typeof(GigyaService));
        string secretKey = ConfigurationManager.AppSettings["GigyaServiceSecretKey"];
        //private object clientParams;
        private const string GET_JWT_PUBLICKEY_METHOD = "accounts.getJWTPublicKey";
        private static readonly HttpClient httpClient = new HttpClient();

        public async Task<JWTPublicKey> GetJWTPublicKey(string apiKey, string apiDomain)
        {
            return await Task.Run(() =>
            {
                try
                {
                    log.Info("----- Gigya Request Start -----");

                    log.Debug("Method: " + GET_JWT_PUBLICKEY_METHOD);
                    log.Debug("API Key: " + apiKey);
                    log.Debug("API Domain: " + apiDomain);
                    log.Debug("Secret Key: " + secretKey);
                    log.Debug("Use HTTPS: true");
                    log.Debug("UseMethodDomain: false");
                    log.Info("Using :: GSRequest(java.lang.String accessToken, java.lang.String apiMethod, GSObject clientParams)  ");
                    /*string fakeSecret = Convert.ToBase64String(
                        Encoding.UTF8.GetBytes("dummy")
                    );*/
                    //GSRequest request = new GSRequest(apiKey, secretKey, GET_JWT_PUBLICKEY_METHOD, null, true);
                    GSRequest request = new GSRequest(apiKey, null, GET_JWT_PUBLICKEY_METHOD, null, true);
                    
                    request.APIDomain = apiDomain;
                    request.UseMethodDomain = false;
                    log.Info("Sending request to Gigya API");
                    GSResponse response = request.Send();
                    log.Info("Response received from Gigya");

                    if (response.GetErrorCode() == 0)
                    {
                        string json = response.GetData().ToJsonString();
                        log.Debug("Raw Response: " + json);
                        var result = JsonConvert.DeserializeObject<JWTPublicKey>(json);
                        log.Info("Successfully parsed JWT public key");

                        return result;
                    }
                    else
                    {
                        log.Error($"Gigya Error Code: {response.GetErrorCode()}");
                        log.Error($"Gigya Error Message: {response.GetErrorMessage()}");

                        throw new Exception(response.GetErrorMessage());
                    }
                }
                catch (Exception ex)
                {
                    log.Error("Exception occurred", ex);
                    throw new Exception("Gigya SDK Error: " + ex.Message);
                }
            });
        }

        public async Task<JWTPublicKey> GetJWTPublicKeyWithJwtAuth(string globalApiKey, string apiDomain, string userKey, string privateKeyPem)
        {
            try
            {
                log.Info("----- Gigya JWT S2S Request Start -----");
                log.Debug("API Domain: " + apiDomain);
                log.Debug("Global API Key: " + globalApiKey);
                log.Debug("User Key: " + userKey);
                log.Debug($"Using PEM length: {(privateKeyPem?.Length ?? 0)} chars");
                if (string.IsNullOrWhiteSpace(privateKeyPem))
                {
                    log.Error("No PEM private key provided to GetJWTPublicKeyWithJwtAuth");
                    throw new ArgumentException("Private key PEM is required for JWT auth");
                }
                // 1. Generate the JWT Token using BouncyCastle
                string bearerToken = JwtGenerator.GenerateFromPkcs8Pem(userKey, privateKeyPem);
                log.Info("Successfully generated JWT Bearer token.");

                // 2. Prepare the HTTP POST request (Postman collection uses POST)
                string url = $"https://{apiDomain}/{GET_JWT_PUBLICKEY_METHOD}";
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, url);

                // Add Authorization header
                requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

                // Add Form URL Encoded body payload
                var requestData = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("apiKey", globalApiKey)
                };
                requestMessage.Content = new FormUrlEncodedContent(requestData);

                log.Info($"Sending S2S HTTP POST to {url}");

                // 3. Execute request
                var responseMessage = await httpClient.SendAsync(requestMessage);
                string responseString = await responseMessage.Content.ReadAsStringAsync();

                log.Debug($"Raw Response Status Code: {responseMessage.StatusCode}");
                log.Debug($"Raw Response Body: {responseString}");

                if (responseMessage.IsSuccessStatusCode)
                {
                    // Parse response directly to JObject first to check Gigya's internal errorCode if wrapped
                    Newtonsoft.Json.Linq.JObject jsonResponse = Newtonsoft.Json.Linq.JObject.Parse(responseString);
                    int? errorCode = jsonResponse["errorCode"]?.ToObject<int?>();

                    if (errorCode != null && errorCode != 0)
                    {
                        string errorMessage = jsonResponse["errorMessage"]?.ToObject<string>();
                        log.Error($"Gigya API Error Code: {errorCode}");
                        log.Error($"Gigya API Error Message: {errorMessage}");
                        throw new Exception(errorMessage ?? "Unknown Gigya Error");
                    }

                    // Deserialize to the requested model
                    var result = jsonResponse.ToObject<JWTPublicKey>();
                    log.Info("Successfully parsed JWT public key from Gigya Global API");
                    return result;
                }
                else
                {
                    log.Error($"HTTP Request failed with status code: {responseMessage.StatusCode}");
                    throw new Exception($"HTTP Error: {(int)responseMessage.StatusCode} {responseMessage.ReasonPhrase}");
                }
            }
            catch (Exception ex)
            {
                log.Error("Exception occurred in GetJWTPublicKeyWithJwtAuth", ex);
                throw;
            }
        }

        public async Task<JWTPublicKey> GetJWTPublicKeyWithCertAuth(string globalApiKey, string apiDomain, string userKey, string certThumbprint)
        {
            try
            {
                log.Info("----- Gigya Certificate S2S Request Start -----");
                log.Debug("API Domain: " + apiDomain);
                log.Debug("Global API Key: " + globalApiKey);
                log.Debug("User Key: " + userKey);
                log.Debug("Cert Thumbprint: " + certThumbprint);

                // 1. Generate the JWT Token using certificate from Windows Certificate Store
                string bearerToken = JwtGenerator.GenerateFromCertificateThumbprint(userKey, certThumbprint);
                log.Info("Successfully generated JWT Bearer token from certificate.");

                // 2. Prepare the HTTP POST request (Postman collection uses POST)
                string url = $"https://{apiDomain}/{GET_JWT_PUBLICKEY_METHOD}";
                var requestMessage = new HttpRequestMessage(HttpMethod.Post, url);

                // Add Authorization header
                requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

                // Add Form URL Encoded body payload
                var requestData = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("apiKey", globalApiKey)
                };
                requestMessage.Content = new FormUrlEncodedContent(requestData);

                log.Info($"Sending S2S HTTP POST to {url}");

                // 3. Execute request
                var responseMessage = await httpClient.SendAsync(requestMessage);
                string responseString = await responseMessage.Content.ReadAsStringAsync();

                log.Debug($"Raw Response Status Code: {responseMessage.StatusCode}");
                log.Debug($"Raw Response Body: {responseString}");

                if (responseMessage.IsSuccessStatusCode)
                {
                    // Parse response directly to JObject first to check Gigya's internal errorCode if wrapped
                    Newtonsoft.Json.Linq.JObject jsonResponse = Newtonsoft.Json.Linq.JObject.Parse(responseString);
                    int? errorCode = jsonResponse["errorCode"]?.ToObject<int?>();

                    if (errorCode != null && errorCode != 0)
                    {
                        string errorMessage = jsonResponse["errorMessage"]?.ToObject<string>();
                        log.Error($"Gigya API Error Code: {errorCode}");
                        log.Error($"Gigya API Error Message: {errorMessage}");
                        throw new Exception(errorMessage ?? "Unknown Gigya Error");
                    }

                    // Deserialize to the requested model
                    var result = jsonResponse.ToObject<JWTPublicKey>();
                    log.Info("Successfully parsed JWT public key from Gigya Global API using certificate auth");
                    return result;
                }
                else
                {
                    log.Error($"HTTP Request failed with status code: {responseMessage.StatusCode}");
                    throw new Exception($"HTTP Error: {(int)responseMessage.StatusCode} {responseMessage.ReasonPhrase}");
                }
            }
            catch (Exception ex)
            {
                log.Error("Exception occurred in GetJWTPublicKeyWithCertAuth", ex);
                throw;
            }
        }



        // Internal debug helper: validate certificate presence and ACLs for the given thumbprint
        public CertificateStatus ValidateCertificateThumbprint(string thumbprint,
            StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            var status = new CertificateStatus { Thumbprint = thumbprint };
            try
            {
                if (string.IsNullOrWhiteSpace(thumbprint))
                {
                    status.Message = "Thumbprint is empty";
                    log.Warn("Thumbprint is empty");
                    return status;
                }

                var normalized = thumbprint.Replace(" ", string.Empty).ToUpperInvariant();
                var store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
                if (certs == null || certs.Count == 0)
                {
                    status.Found = false;
                    status.Message = "Certificate not found";
                    store.Close();
                    return status;
                }

                status.Found = true;
                var cert = certs[0];
                status.Subject = cert.Subject;
                status.Issuer = cert.Issuer;
                status.NotBefore = cert.NotBefore;
                status.NotAfter = cert.NotAfter;

                // Check for private key and try a small sign operation to verify ACLs
                try
                {
                    using (var rsa = cert.GetRSAPrivateKey())
                    {
                        status.HasPrivateKey = rsa != null;
                        if (rsa != null)
                        {
                            status.KeySize = rsa.KeySize;
                            // Try to sign a small piece of data
                            var data = new byte[16];
                            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(data);
                            var sig = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                            status.CanSign = sig != null && sig.Length > 0;
                        }
                    }
                }
                catch (Exception ex)
                {
                    status.CanSign = false;
                    status.Message = "Private key present but unable to use it: " + ex.Message;
                }

                store.Close();
                return status;
            }
            catch (Exception ex)
            {
                status.Message = "Exception while validating certificate: " + ex.Message;
                log.Error(status.Message, ex);
                return status;
            }
        }
    }
}