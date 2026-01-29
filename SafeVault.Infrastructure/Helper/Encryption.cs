using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SafeVault.Infrastructure.Helper
{
    public static class Encryption
    {
        public static string? Encrypt(string? clearText, string key)
        {
            if (clearText == null) { return null; }
            string EncryptionKey = key;
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            byte[] salt = GenerateSalt();


            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(memoryStream, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }

                    clearText = Convert.ToBase64String(memoryStream.ToArray());
                    clearText = Convert.ToBase64String(CombineSaltAndEncryptedPassword(salt, clearText));
                }
            }
            return clearText;
        }
        public static string? Decrypt(string? cipherText, string key)
        {
            if (cipherText == null) { return null; }

            string EncryptionKey = key;
            (byte[] salt, string encryptedData) = SplitSaltAndEncryptedPassword(Convert.FromBase64String(cipherText));

            cipherText = encryptedData.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }

        private static byte[] GenerateSalt()
        {
            using RandomNumberGenerator randomNumberGenerator = RandomNumberGenerator.Create();
            byte[] salt = new byte[16]; // 128-bit salt is recommended
            randomNumberGenerator.GetBytes(salt);
            return salt;
        }

        private static byte[] CombineSaltAndEncryptedPassword(byte[] salt, string encryptedPassword)
        {
            byte[] encryptedPasswordBytes = Encoding.UTF8.GetBytes(encryptedPassword);
            byte[] combinedBytes = new byte[salt.Length + encryptedPasswordBytes.Length];

            Array.Copy(salt, 0, combinedBytes, 0, salt.Length);
            Array.Copy(encryptedPasswordBytes, 0, combinedBytes, salt.Length, encryptedPasswordBytes.Length);

            return combinedBytes;

        }

        private static (byte[] salt, string encryptedPassword) SplitSaltAndEncryptedPassword(byte[] combinedBytes)
        {
            byte[] salt = new byte[16]; // Salt length
            Array.Copy(combinedBytes, 0, salt, 0, salt.Length);

            byte[] encryptedBytes = new byte[combinedBytes.Length - salt.Length];
            Array.Copy(combinedBytes, salt.Length, encryptedBytes, 0, encryptedBytes.Length);



            string encryptedPassword = Encoding.UTF8.GetString(encryptedBytes); // Use base64 encoding

            return (salt, encryptedPassword);

        }

        public static string GetStreamHash(MemoryStream stream)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                stream.Position = 0;  // Ensure you read from the start of the stream

                byte[] hashBytes = sha256.ComputeHash(stream);

                stream.Position = 0;

                return ConvertHashToString(hashBytes);

            }
        }

        private static string ConvertHashToString(byte[] hashBytes)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2"));
            }
            return sb.ToString();
        }

        public static string GetHash(string text, HashAlgorithm algorithm = null, Encoding encoding = null)
        {
            byte[] message = (encoding == null) ? Encoding.UTF8.GetBytes(text) : encoding.GetBytes(text);
            algorithm = algorithm ?? new SHA256Managed();
            byte[] hashValue = algorithm.ComputeHash(message);

            // Start with an empty string and concatenate the hexadecimal 2-character representation of each byte in variable hashValue
            return hashValue.Aggregate(string.Empty, (current, x) => current + string.Format("{0:x2}", x));
        }

    }
}
