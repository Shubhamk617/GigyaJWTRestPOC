using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using log4net;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Pkcs;

namespace GigyaJWTRestPOC.Services
{
    public class JwtGenerator
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(JwtGenerator));
        // Backwards-compatible Generate method. Delegates to PKCS#8 compatible implementation.
        public static string Generate(string userKey, string privateKeyPem)
        {
            return GenerateFromPkcs8Pem(userKey, privateKeyPem);
        }

        // New helper: generate JWT using an RSA private key stored in the Windows Certificate Store
        public static string GenerateFromCertificateThumbprint(string userKey, string thumbprint,
            StoreName storeName = StoreName.My, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            if (string.IsNullOrWhiteSpace(userKey)) throw new ArgumentNullException(nameof(userKey));
            if (string.IsNullOrWhiteSpace(thumbprint)) throw new ArgumentNullException(nameof(thumbprint));

            // Normalize thumbprint (remove spaces)
            var normalized = thumbprint.Replace(" ", string.Empty).ToUpperInvariant();

            var store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
                if (certs == null || certs.Count == 0)
                    throw new InvalidOperationException($"Certificate with thumbprint '{thumbprint}' not found in {storeLocation}\\{storeName}.");

                var cert = certs[0];
                var rsa = cert.GetRSAPrivateKey();
                if (rsa == null)
                    throw new InvalidOperationException("Certificate does not have an RSA private key or the process lacks access to it.");

                log.Info("Generating JWT from certificate thumbprint");
                log.Debug($"userKey={userKey}, thumbprint={thumbprint}, store={storeLocation}\\{storeName}");

                var securityKey = new RsaSecurityKey(rsa)
                {
                    KeyId = userKey
                };

                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                var jti = GenerateJti();
                log.Debug($"Generated jti={jti}, iat={now}");

                var payload = new JwtPayload
                {
                    { "iat", now },
                    { "jti", jti }
                };

                var header = new JwtHeader(credentials);
                header["kid"] = userKey;

                var token = new JwtSecurityToken(header, payload);

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                log.Info("JWT successfully generated from certificate");
                log.Debug($"JWT size={tokenString?.Length}");
                return tokenString;
            }
            finally
            {
                try { store.Close(); } catch { }
            }
        }

        // New method: generate JWT using a PKCS#8 PEM private key via BouncyCastle
        // This is compatible with .NET Framework 4.7.2 where ImportFromPem is not available.
        public static string GenerateFromPkcs8Pem(string userKey, string privateKeyPem)
        {
            if (string.IsNullOrWhiteSpace(userKey)) throw new ArgumentNullException(nameof(userKey));
            if (string.IsNullOrWhiteSpace(privateKeyPem)) throw new ArgumentNullException(nameof(privateKeyPem));
            log.Info("Generating JWT from PEM private key");
            log.Debug($"userKey={userKey}, pemLength={(privateKeyPem?.Length ?? 0)} chars");

            // Parse the PEM and create an RSA instance
            var rsa = CreateRsaFromPrivateKeyPem(privateKeyPem);

            var securityKey = new RsaSecurityKey(rsa)
            {
                KeyId = userKey
            };

            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);

            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            var jti = GenerateJti();
            log.Debug($"Generated jti={jti}, iat={now}");

            var payload = new JwtPayload
            {
                { "iat", now },
                { "jti", jti }
            };

            var header = new JwtHeader(credentials);
            header["kid"] = userKey;

            var token = new JwtSecurityToken(header, payload);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            log.Info("JWT successfully generated from PEM");
            log.Debug($"JWT size={tokenString?.Length}");
            return tokenString;
        }

        // Helper: create an RSA instance from a PKCS#8 / PKCS#1 PEM private key using BouncyCastle
        public static RSA CreateRsaFromPrivateKeyPem(string privateKeyPem)
        {
            if (string.IsNullOrWhiteSpace(privateKeyPem)) throw new ArgumentException("PEM is empty", nameof(privateKeyPem));

            try 
            {
                string base64 = privateKeyPem;
                int beginIdx = base64.IndexOf("-----BEGIN");
                if (beginIdx >= 0) {
                    int endLineIdx = base64.IndexOf('\n', beginIdx);
                    if (endLineIdx > 0 && endLineIdx < base64.Length) {
                        base64 = base64.Substring(endLineIdx + 1);
                    } else {
                        int endDash = base64.IndexOf("-----", beginIdx + 10);
                        if (endDash > 0) base64 = base64.Substring(endDash + 5);
                    }
                }
                
                int endIdx = base64.IndexOf("-----END");
                if (endIdx >= 0) {
                    base64 = base64.Substring(0, endIdx);
                }
                
                var sb = new StringBuilder();
                foreach (char c in base64) {
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
                        sb.Append(c);
                    }
                }
                base64 = sb.ToString();

                int mod4 = base64.Length % 4;
                if (mod4 > 0) {
                    base64 += new string('=', 4 - mod4);
                }

                byte[] derBytes = Convert.FromBase64String(base64);
                var keyParam = PrivateKeyFactory.CreateKey(derBytes);
                
                var rsaParams = keyParam as RsaPrivateCrtKeyParameters;
                if (rsaParams == null)
                    throw new Exception("Parsed successfully but wrong key type.");

                return DotNetUtilities.ToRSA(rsaParams);
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"AZURE HARDENED PARSE ERROR. Ex: {ex.Message} | Total length: {privateKeyPem.Length}", nameof(privateKeyPem), ex);
            }
        }

        // Generate JTI following the same pattern as the Postman snippet provided by Gigya.
        // This mimics a UUIDv4-like value but produced using a cryptographically secure RNG.
        private static string GenerateJti()
        {
            // Template: 10000000-1000-4000-8000-100000000000
            var template = "10000000-1000-4000-8000-100000000000";
            var sb = new StringBuilder(template.Length);
            using (var rng = RandomNumberGenerator.Create())
            {
                for (int i = 0; i < template.Length; i++)
                {
                    char c = template[i];
                    if (c == '0' || c == '1' || c == '8')
                    {
                        // generate a random byte
                        var b = new byte[1];
                        rng.GetBytes(b);
                        int r = b[0] & 0xFF;
                        // emulate the JS expression: (+c ^ crypto.getRandomValues(...)[0] & 15 >> +c / 4)
                        int ci = c - '0';
                        int val = (ci ^ (r & 15)) >> (ci / 4);
                        sb.Append(val.ToString("x"));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                }
            }
            return sb.ToString();
        }
    }
}