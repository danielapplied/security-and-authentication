using System.Text.RegularExpressions;
using System.Net;

namespace SecurityAndAuth
{
    public static class InputSanitizer
    {
        // 🔹 Remove dangerous SQL/XSS characters
        public static string SanitizeString(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            // Remove common SQL injection patterns
            string sanitized = Regex.Replace(input, @"(--|\b(SELECT|INSERT|DELETE|DROP|UPDATE|ALTER)\b)", "", RegexOptions.IgnoreCase);

            // Remove special characters often used in attacks
            sanitized = Regex.Replace(sanitized, @"[;'\-]", "");

            return sanitized.Trim();
        }

        // 🔹 Validate Email format
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        }

        // 🔹 Encode output to prevent XSS
        public static string EncodeForHtml(string input)
        {
            return WebUtility.HtmlEncode(input);
        }

        // 🔹 Strong validation for names
        public static bool IsValidName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return false;

            // Allow letters, spaces, hyphens
            return Regex.IsMatch(name, @"^[a-zA-Z\s\-]{3,100}$");
        }
    }
}
