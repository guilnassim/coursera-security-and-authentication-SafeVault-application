using SafeVault.Infrastructure.Helper;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace YourProject.Tests
{
    public class EncryptionTests
    {
        private const string Key = "UnitTest-Key-For-Encryption-!@#2026";

        [Fact]
        public void Encrypt_WithNull_ReturnsNull()
        {
            // Act
            var result = Encryption.Encrypt(null, Key);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void Decrypt_WithNull_ReturnsNull()
        {
            // Act
            var result = Encryption.Decrypt(null, Key);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public void Encrypt_Then_Decrypt_RoundTrip_ReturnsOriginal()
        {
            // Arrange
            var original = "Mallorca – Inventory 123";

            // Act
            var cipher = Encryption.Encrypt(original, Key);
            var roundTrip = Encryption.Decrypt(cipher, Key);

            // Assert
            Assert.NotNull(cipher);
            Assert.Equal(original, roundTrip);
        }

        [Fact]
        public void Encrypt_ProducesBase64_And_NotEqualToPlaintext()
        {
            // Arrange
            var original = "plain-text";

            // Act
            var cipher = Encryption.Encrypt(original, Key);

            // Assert
            Assert.NotNull(cipher);
            Assert.NotEqual(original, cipher);

            // Is Base64?
            Span<byte> buffer = new byte[cipher!.Length];
            bool isBase64 = Convert.TryFromBase64String(cipher, buffer, out _);
            Assert.True(isBase64);
        }

        [Fact]
        public void EmptyString_RoundTrip_ReturnsEmpty()
        {
            // Arrange
            var original = string.Empty;

            // Act
            var cipher = Encryption.Encrypt(original, Key);
            var roundTrip = Encryption.Decrypt(cipher, Key);

            // Assert
            Assert.Equal(string.Empty, roundTrip);
        }

        [Fact]
        public void Decrypt_WithWrongKey_ThrowsCryptographicException()
        {
            // Arrange
            var original = "secret";
            var cipher = Encryption.Encrypt(original, Key);

            // Act & Assert
            Assert.Throws<CryptographicException>(() =>
            {
                var _ = Encryption.Decrypt(cipher, "WRONG-KEY");
            });
        }

        [Fact]
        public void Decrypt_WithTamperedCipherText_Throws()
        {
            // Arrange
            var original = "secret";
            var cipher = Encryption.Encrypt(original, Key);
            Assert.NotNull(cipher);

            // Tamper: flip a char safely in the Base64 string
            char[] chars = cipher!.ToCharArray();
            // Change the first non-padding char to a different Base64-valid char
            for (int i = 0; i < chars.Length; i++)
            {
                if (chars[i] != 'A' && chars[i] != '=')
                {
                    chars[i] = 'A';
                    break;
                }
            }

            var tampered = new string(chars);

            // Act & Assert
            // Depending on damage, this can be FormatException or CryptographicException.
            Assert.ThrowsAny<Exception>(() => Encryption.Decrypt(tampered, Key));
        }

        [Fact]
        public void GetStreamHash_KnownInput_ReturnsExpectedSha256Hex()
        {
            // Arrange
            var text = "hello"; // UTF-8
            var bytes = Encoding.UTF8.GetBytes(text);
            using var ms = new MemoryStream(bytes);

            // Precomputed SHA-256("hello") in hex (lowercase):
            // 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
            var expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

            // Act
            var hash = Encryption.GetStreamHash(ms);

            // Assert
            Assert.Equal(expected, hash);

            // And the method resets stream.Position to 0
            Assert.Equal(0, ms.Position);
        }

        [Fact]
        public void GetHash_KnownVector_abc_ReturnsExpectedSha256Hex()
        {
            // Arrange
            var text = "abc";
            // SHA-256("abc") in lowercase hex:
            var expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

            // Act
            var actual = Encryption.GetHash(text);

            // Assert
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void GetHash_WithExplicitAlgorithm_AndCustomEncoding_Works()
        {
            // Arrange
            var text = "Mallorca";
            using var algo = SHA256.Create();
            var encoding = Encoding.Unicode; // UTF-16LE

            // Compute expected independently:
            var expected = BitConverter.ToString(algo.ComputeHash(encoding.GetBytes(text)))
                                       .Replace("-", "")
                                       .ToLowerInvariant();

            // Act
            var actual = Encryption.GetHash(text, algo, encoding);

            // Assert
            Assert.Equal(expected, actual);
        }
    }
}