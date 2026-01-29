
using SafeVault.Application.Security;
using Xunit;

public class XssTests
{
    [Theory]
    [InlineData("<img src=x onerror=alert(1)>", "&lt;img src=x onerror=alert(1)&gt;")]
    [InlineData("<script>alert('x')</script>", "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;")]
    public void Output_Is_Encoded(string input, string expected)
    {
        var encoded = InputSanitizer.HtmlEncode(input);
        Assert.Equal(expected, encoded);
    }
}
