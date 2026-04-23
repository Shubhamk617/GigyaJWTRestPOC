using GigyaJWTRestPOC.Services;// for PemFileHelper
using log4net;
using System.Configuration;
using System.Threading.Tasks;
using System.Web.Http;

namespace GigyaJWTRestPOC.Controllers
{
    [RoutePrefix("api/gigya")]
    public class GigyaController : ApiController
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(GigyaController));
        private readonly GigyaService _service;
        public GigyaController()
        {
            _service = new GigyaService();
        }

        // New endpoint: fetch JWT public key using certificate-based JWT auth (Global API Key)
        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("jwt-public-key-global")]
        public async Task<IHttpActionResult> GetJWTPublicKeyGlobal()
        {
            log.Info("API Hit: /api/gigya/jwt-public-key-global");
            string globalApiKey = ConfigurationManager.AppSettings["GigyaGlobalApiKey"];
            string apiDomain = ConfigurationManager.AppSettings["GigyaGlobalApiDomain"]; // or use global domain if different
            string userKey = ConfigurationManager.AppSettings["GigyaGlobalUserKey"];
            string privateKeyPem = null;
            // support reading PEM from a file path configured in GigyaPrivateKeyPath
            var pemPathConfig = ConfigurationManager.AppSettings["GigyaPrivateKeyPath"];
            if (!string.IsNullOrWhiteSpace(pemPathConfig))
            {
                try
                {
                    privateKeyPem = PemFileHelper.ReadPemFromConfigPath("GigyaPrivateKeyPath");
                }
                catch (System.Exception ex)
                {
                    log.Error("Failed to read PEM from configured path", ex);
                    // fall back to GigyaGlobalPrivateKey if present
                    privateKeyPem = ConfigurationManager.AppSettings["GigyaGlobalPrivateKey"];
                }
            }
            else
            {
                privateKeyPem = ConfigurationManager.AppSettings["GigyaGlobalPrivateKey"];
            }

            try
            {
                var result = await _service.GetJWTPublicKeyWithJwtAuth(globalApiKey, apiDomain, userKey, privateKeyPem);
                return Ok(result);
            }
            catch (System.Exception ex)
            {
                log.Error("Controller Exception", ex);
                return InternalServerError(ex);
            }
        }
        // New endpoint: fetch JWT public key using certificate-based JWT auth (Global API Key)
        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("jwt-public-key-global-windows-cert")]
        public async Task<IHttpActionResult> GetJWTPublicKeyGlobalWindowsCert()
        {
            log.Info("API Hit: /api/gigya/jwt-public-key-global-windows-cert");
            string globalApiKey = ConfigurationManager.AppSettings["GigyaGlobalApiKey"];
            string apiDomain = ConfigurationManager.AppSettings["GigyaGlobalApiDomain"]; // or use global domain if different
            string userKey = ConfigurationManager.AppSettings["GigyaGlobalUserKey"];
            string certThumbprint = ConfigurationManager.AppSettings["GigyaGlobalCertThumbprint"];

            try
            {
                var result = await _service.GetJWTPublicKeyWithCertAuth(globalApiKey, apiDomain, userKey, certThumbprint);
                return Ok(result);
            }
            catch (System.Exception ex)
            {
                log.Error("Controller Exception", ex);
                return InternalServerError(ex);
            }
        }

        // Internal debug endpoint: validate certificate presence and ACL for the configured thumbprint
        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("cert-status")]
        public IHttpActionResult GetCertificateStatus()
        {
            log.Info("API Hit: /api/gigya/cert-status");
            string certThumbprint = ConfigurationManager.AppSettings["GigyaGlobalCertThumbprint"];
            try
            {
                var status = _service.ValidateCertificateThumbprint(certThumbprint);
                return Ok(status);
            }
            catch (System.Exception ex)
            {
                log.Error("Controller Exception in GetCertificateStatus", ex);
                return InternalServerError(ex);
            }
        }

        [System.Web.Http.HttpGet]
        [System.Web.Http.Route("jwt-public-key")]
        public async Task<IHttpActionResult> GetJWTPublicKey()
        {
            log.Info("API Hit: /api/gigya/jwt-public-key");
            string apiKey = ConfigurationManager.AppSettings["GigyaServiceApiKey"];
            string apiDomain = ConfigurationManager.AppSettings["GigyaServiceApiDomain"];

            try
            {
                var result = await _service.GetJWTPublicKey(apiKey, apiDomain);
                return Ok(result);
            }
            catch (System.Exception ex)
            {
                log.Error("Controller Exception", ex);
                return InternalServerError(ex);
            }
        }
        
    }
}