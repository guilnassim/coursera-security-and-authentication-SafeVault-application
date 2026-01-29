using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;


namespace SafeVault.Domain.Entities
{
    /// <summary>
    /// Domain entity for user profile records stored by the application (not Identity).
    /// </summary>
    public class UserRecord
    {
        private static readonly Regex Pattern = new(@"^[a-zA-Z0-9_.-]{3,50}$", RegexOptions.Compiled);
        public Guid Id { get; set; } = Guid.NewGuid();
        private string _userName;

        public string Username
        {
            get { return _userName; }
            set { _userName = ValidName(value); }
        }
        private string _email;

        public string Email
        {
            get { return _email; }
            set { _email = ValidEmail(value); }
        }
        public string? UserPrivateDetail { get; set; }

        private string ValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) throw new ArgumentException("Email is required.");
            string normalized = email.Trim();
            if (normalized.Length > 254) throw new ArgumentException("Email too long.");
            try { return new MailAddress(normalized).Address; }
            catch
            {
                throw new ArgumentException("Invalid email format.");
            }            
        }
        private string ValidName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("Username is required.");
            var trimmed = name.Trim();
            if (!Pattern.IsMatch(trimmed)) throw new ArgumentException("Username must be 3-50 chars [a-zA-Z0-9_.-].");            
            return trimmed;
        }

    }
}

