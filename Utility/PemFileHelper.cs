using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Configuration;
using log4net;

namespace GigyaJWTRestPOC.Services
{
    internal static class PemFileHelper
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(PemFileHelper));

        // Read PEM content from a config key that contains a relative or absolute path
        public static string ReadPemFromConfigPath(string configKey)
        {
            if (string.IsNullOrWhiteSpace(configKey)) throw new ArgumentNullException(nameof(configKey));

            var configured = ConfigurationManager.AppSettings[configKey];
            if (string.IsNullOrWhiteSpace(configured))
                throw new InvalidOperationException($"Missing appSetting '{configKey}' or it is empty.");

            var path = configured;
            if (!Path.IsPathRooted(path))
                path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, path);

            log.Debug($"Resolving PEM path from config key '{configKey}' -> '{path}'");

            return ReadPemFromFile(path);
        }

        // Read and extract first PEM block from a given file path
        public static string ReadPemFromFile(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));
            if (!File.Exists(path)) throw new FileNotFoundException("PEM file not found", path);

            var txt = File.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(txt)) throw new ArgumentException("PEM file is empty", nameof(path));

            // Match the first PEM block: -----BEGIN xxx----- ... -----END xxx-----
            var pattern = @"-----BEGIN [^-]+-----[\r\n]+([\s\S]*?)[\r\n]+-----END [^-]+-----";
            var m = Regex.Match(txt, pattern, RegexOptions.Singleline);
            if (!m.Success)
            {
                log.Error($"No valid PEM block found in file '{path}'");
                throw new ArgumentException("Invalid PEM content or no PEM block found in file.");
            }

            var pem = m.Value.Trim();

            // Basic normalization for common malformed headers (do not over-aggressive replace)
            pem = pem.Replace("-----BEGIN RSA PRIVATE KEY--PKCS1---", "-----BEGIN RSA PRIVATE KEY-----")
                     .Replace("-----END RSA PRIVATE KEY---PKCS1--", "-----END RSA PRIVATE KEY-----")
                     .Replace("-----BEGIN PRIVATE KEY--PKCS8---", "-----BEGIN PRIVATE KEY-----")
                     .Replace("-----END PRIVATE KEY----PKCS8-", "-----END PRIVATE KEY-----");

            log.Debug($"Extracted PEM block from '{path}', length={pem.Length}");
            return pem;
        }
    }
}
