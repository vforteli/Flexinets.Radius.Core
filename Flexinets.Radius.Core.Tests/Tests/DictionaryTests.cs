using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using System.IO;
using System.Linq;
using System.Text;

namespace Flexinets.Radius.Core.Tests;

[TestFixture]
public class DictionaryTests
{
    [TestCase]
    public void TestLastItemPrevails()
    {
        const string dictionaryString =
            """
            Attribute	1	User-Name	string
            Attribute	2	User-Password	octet
            Attribute	3	User-Name	octet

            VendorSpecificAttribute	5	3	Acc-Input-Errors	integer
            VendorSpecificAttribute	5	4	Acc-Input-Errors	octet
            """;

        var dictionaryStream = new MemoryStream(Encoding.UTF8.GetBytes(dictionaryString));
        var dictionary = new RadiusDictionary(dictionaryStream, NullLogger<RadiusDictionary>.Instance);

        Assert.Multiple(() =>
        {
            var attributeByName = dictionary.GetAttribute("User-Name");
            Assert.That(attributeByName.Code, Is.EqualTo(3));
            Assert.That(attributeByName.Type, Is.EqualTo("octet"));

            var attributeByCode = dictionary.Attributes[3];
            Assert.That(attributeByCode.Name, Is.EqualTo("User-Name"));

            var vendorAttributeByName = dictionary.GetAttribute("User-Name");
            Assert.That(vendorAttributeByName.Code, Is.EqualTo(3));
            Assert.That(vendorAttributeByName.Type, Is.EqualTo("octet"));

            var vendorAttributeByCode =
                dictionary.VendorSpecificAttributes.Single(o => o.VendorId == 5 && o.VendorCode == 4);
            Assert.That(vendorAttributeByCode.Name, Is.EqualTo("Acc-Input-Errors"));
            Assert.That(vendorAttributeByCode.Type, Is.EqualTo("octet"));
        });
    }
}