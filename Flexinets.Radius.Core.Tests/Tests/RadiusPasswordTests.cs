using System.Text;
using NUnit.Framework;

namespace Flexinets.Radius.Core.Tests;

public class RadiusPasswordTests
{
    private static readonly byte[] DefaultSecret = "xyzzy5461"u8.ToArray();

    /// <summary>
    /// Test passwords with length > 16        
    /// </summary>
    [TestCase("123456789")]
    [TestCase("12345678901234567890")]
    [TestCase("123")]
    [TestCase("12345678901234567890blablabla")]
    public void PasswordEncryptDecrypt(string password)
    {
        const string authenticator = "1234567890123456";

        var encrypted = RadiusPassword.Encrypt(DefaultSecret, Encoding.UTF8.GetBytes(authenticator),
            Encoding.UTF8.GetBytes(password));

        var decrypted = RadiusPassword.Decrypt(DefaultSecret, Encoding.UTF8.GetBytes(authenticator),
            encrypted);

        Assert.That(decrypted, Is.EqualTo(password));
    }
}