using SafeVault.Application.Security;
using Xunit;

public class InputValidationTests
{
    [Theory]
    [InlineData("alice", "alice")]
    [InlineData("alice<script>", "alice")]
    [InlineData("bob'; DROP TABLE Users;--", "bob")]
    [InlineData("John_Doe-99", "John_Doe-99")]
    public void SanitizeStrict_WhitelistsChars(string input, string expectedPrefix)
    {
        var sanitized = InputSanitizer.SanitizeStrict(input, "-_.");
        Assert.StartsWith(expectedPrefix, sanitized);
        Assert.DoesNotContain("<", sanitized);
        Assert.DoesNotContain(">", sanitized);
        Assert.DoesNotContain("'", sanitized);
        Assert.DoesNotContain(";", sanitized);
    }

    [Fact]
    public void SanitizeStrict_NotAllowedSpecials()
    {
        var stringNotAllowedSpecials = "user+tag-@example.com<script>";
        var sanitized = InputSanitizer.SanitizeStrict(stringNotAllowedSpecials);
        Assert.Equal("usertagexamplecom", sanitized);
    }

    [Fact]
    public void Email_SanitizeAndValidate()
    {
        var email = "user+tag-@example.com<script>";
        var cleaned = InputSanitizer.SanitizeAndValidateEmail(email);
        Assert.Equal("user+tag-@example.com", cleaned);
    }

    [Fact]
    public void HtmlEncode_EncodesScripts()
    {
        var encoded = InputSanitizer.HtmlEncode("<script>alert(1)</script>");
        Assert.Contains("&lt;script&gt;", encoded);
    }
}
