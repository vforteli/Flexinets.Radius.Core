using NUnit.Framework;

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

        var dictionary = RadiusDictionary.Parse(dictionaryString);

        Assert.Multiple(() =>
        {
            var attributeByName = dictionary.GetAttribute("User-Name")!;
            Assert.That(attributeByName.Code, Is.EqualTo(3));
            Assert.That(attributeByName.Type, Is.EqualTo("octet"));

            var attributeByCode = dictionary.GetAttribute(3);
            Assert.That(attributeByCode!.Name, Is.EqualTo("User-Name"));

            var vendorAttributeByName = dictionary.GetAttribute("User-Name")!;
            Assert.That(vendorAttributeByName.Code, Is.EqualTo(3));
            Assert.That(vendorAttributeByName.Type, Is.EqualTo("octet"));

            var vendorAttributeByCode = dictionary.GetVendorAttribute(5, 4)!;
            Assert.That(vendorAttributeByCode.Name, Is.EqualTo("Acc-Input-Errors"));
            Assert.That(vendorAttributeByCode.Type, Is.EqualTo("octet"));
        });
    }
}