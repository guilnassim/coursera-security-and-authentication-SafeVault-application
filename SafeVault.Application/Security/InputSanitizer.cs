using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace SafeVault.Application.Security
{
    /// <summary>
    /// OWASP-aligned input sanitation: whitelist approach + HTML encoding for output.
    /// Allows letters, digits, and explicitly specified special characters.
    /// </summary>
    public static class InputSanitizer
    {
        /// <param name="input">Raw user input (e.g., username)</param>
        /// <param name="allowedSpecials">String of allowed special characters, e.g., "-_."</param>
        /// <returns>Sanitized string containing only letters, digits, and allowed specials.</returns>
        public static string SanitizeStrict(string? input, string? allowedSpecials = "" )
        {

            if (string.IsNullOrWhiteSpace(input)) return string.Empty;
            string cleaned = Regex.Replace(input, "<.*?>", string.Empty);
            var specialsEscaped = Regex.Escape(allowedSpecials);
            specialsEscaped = specialsEscaped.Replace("-", "\\-");
            // Normalize spaces and trim
            var normalized = cleaned.Trim();
            // Build whitelist regex: letters+digits + explicit specials
            var pattern = $"[A-Za-z0-9{specialsEscaped}]";
            var matches = Regex.Matches(normalized, pattern);
            return string.Concat(matches.Select(m => m.Value));
        }

        /// <summary>
        /// Encodes for safe HTML output to prevent XSS; use in views/responses.
        /// </summary>
        public static string HtmlEncode(string input)
        {
            return HttpUtility.HtmlEncode(input);
        }

        /// <summary>
        /// Email validation: restricts to safe characters then checks format via MailAddress.
        /// </summary>
        public static string SanitizeAndValidateEmail(string? email)
        {
            if (string.IsNullOrWhiteSpace(email)) return string.Empty;
            // Allow letters/digits/@._- and plus (+) commonly used for aliases
            var cleaned = SanitizeStrict(email, @"@._-+");
            try
            {
                var addr = new System.Net.Mail.MailAddress(cleaned);
                return addr.Address;
            }
            catch
            {
                return string.Empty; // invalid
            }
        }
    }
}
