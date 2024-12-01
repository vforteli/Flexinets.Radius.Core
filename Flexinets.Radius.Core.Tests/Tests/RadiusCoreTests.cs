using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using Flexinets.Radius.Core.PacketTypes;

namespace Flexinets.Radius.Core.Tests;

[TestFixture]
public class RadiusCoreTests
{
    private static readonly byte[] DefaultSecret = "xyzzy5461"u8.ToArray();
    private static readonly IRadiusDictionary Dictionary = RadiusDictionary.Parse(DefaultDictionary.RadiusDictionary);

    private static readonly RadiusPacketParser RadiusPacketParser =
        new(NullLogger<RadiusPacketParser>.Instance, Dictionary);


    /// <summary>
    /// Create packet and verify bytes
    /// Example from https://tools.ietf.org/html/rfc2865
    /// </summary>
    [TestCase]
    public void TestCreateAccessRequestPacket()
    {
        const string expected =
            "010000380f403f9473978057bd83d5cb98f4227a01066e656d6f02120dbe708d93d413ce3196e43f782a0aee0406c0a80110050600000003";

        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("User-Password", "arctangent");
        packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
        packet.AddAttribute("NAS-Port", 3);

        Assert.That(RadiusPacketParser.GetBytes(packet, DefaultSecret).ToHexString(),
            Is.EqualTo(expected));
    }


    /// <summary>
    /// Create packet and verify bytes, including IPv6 attribute
    /// Example from https://tools.ietf.org/html/rfc2865
    /// </summary>
    [TestCase]
    public void TestCreateAccessRequestPacketIPv6()
    {
        var expected = IPAddress.IPv6Loopback;

        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("User-Password", "arctangent");
        packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
        packet.AddAttribute("Framed-IPv6-Address", expected);
        packet.AddAttribute("NAS-Port", 3);

        var actual = packet.GetAttribute<IPAddress>("Framed-IPv6-Address");
        Assert.That(actual, Is.EqualTo(expected));
    }


    /// <summary>
    /// Create packet and verify bytes
    /// Example from https://tools.ietf.org/html/rfc2865
    /// </summary>
    [TestCase]
    public void TestCreateAccessRequestPacketUnknownAttribute()
    {
        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("hurr", "durr");
        packet.AddAttribute("User-Password", "arctangent");
        packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
        packet.AddAttribute("NAS-Port", 3);

        Assert.That(() => RadiusPacketParser.GetBytes(packet, DefaultSecret),
            Throws.TypeOf<InvalidOperationException>());
    }


    /// <summary>
    /// Create disconnect request packet and verify bytes
    /// </summary>
    [TestCase]
    public void TestCreateDisconnectRequestPacket()
    {
        const string expected = "2801001e2ec8a0da729620319be0140bc28e92682c0a3039303432414638";

        var packet = new DisconnectRequest(1);
        packet.AddAttribute("Acct-Session-Id", "09042AF8");

        Assert.That(RadiusPacketParser.GetBytes(packet, DefaultSecret).ToHexString(), Is.EqualTo(expected));
    }


    /// <summary>
    /// Create status server request packet and verify bytes
    /// </summary>
    [TestCase]
    public void TestCreateStatusServerRequestPacket()
    {
        const string expected = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";

        var packet = new StatusServer(218)
        {
            Authenticator = Utils.StringToByteArray("8a54f4686fb394c52866e302185d0623")
        };

        Assert.That(RadiusPacketParser.GetBytes(packet, DefaultSecret).ToHexString(), Is.EqualTo(expected));
    }


    /// <summary>
    /// Create status server request packet and verify bytes
    /// </summary>
    [TestCase]
    public void TestCreateStatusServerRequestPacketAccounting()
    {
        const string expected = "0cb30026925f6b66dd5fed571fcb1db7ad3882605012e8d6eabda910875cd91fdade26367858";

        var packet = new StatusServer(179)
        {
            Authenticator = Utils.StringToByteArray("925f6b66dd5fed571fcb1db7ad388260")
        };

        Assert.That(RadiusPacketParser.GetBytes(packet, DefaultSecret).ToHexString(),
            Is.EqualTo(expected));
    }


    /// <summary>
    /// Create accounting request        
    /// </summary>
    [TestCase]
    public void TestCreateAndParseAccountingRequestPacket()
    {
        var packet = new AccountingRequest(0);
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("Acct-Status-Type", 2);
        packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
        packet.AddAttribute("NAS-Port", 3);

        var bytes = RadiusPacketParser.GetBytes(packet, DefaultSecret);
        Assert.DoesNotThrow(() => RadiusPacketParser.Parse(bytes, DefaultSecret));
    }


    ///// <summary>
    ///// Create packet and verify bytes
    ///// Example from https://tools.ietf.org/html/rfc2865
    ///// </summary>
    [TestCase]
    public void TestAccountingPacketRequestAuthenticatorSuccess()
    {
        const string packetBytes = "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234";

        var requestAuthenticator = Utils.CalculateRequestAuthenticator(
            DefaultSecret,
            Utils.StringToByteArray(packetBytes));
        var packet = RadiusPacketParser.Parse(Utils.StringToByteArray(packetBytes), DefaultSecret);

        Assert.That(requestAuthenticator.ToHexString(), Is.EqualTo(packet.Authenticator.ToHexString()));
    }


    ///// <summary>
    ///// Create packet and verify bytes
    ///// Example from https://tools.ietf.org/html/rfc2865
    ///// </summary>
    [TestCase]
    public void TestAccountingPacketRequestAuthenticatorFail()
    {
        const string packetBytes = "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234";
        const string secret = "foo";

        Assert.That(
            () => RadiusPacketParser.Parse(Utils.StringToByteArray(packetBytes), Encoding.UTF8.GetBytes(secret)),
            Throws.TypeOf<InvalidOperationException>());
    }


    /// <summary>
    /// Test parsing and rebuilding a packet
    /// </summary>
    [TestCase]
    public void TestPacketParserAndAssembler()
    {
        const string request = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";

        var requestPacket = RadiusPacketParser.Parse(Utils.StringToByteArray(request), DefaultSecret);
        var bytes = RadiusPacketParser.GetBytes(requestPacket, DefaultSecret);

        Assert.That(bytes.ToHexString(), Is.EqualTo(request));
    }


    /// <summary>
    /// Test parsing and rebuilding a packet
    /// </summary>
    [Obsolete("Parsing from stream is obsolete")]
    [TestCase]
    public void TestPacketParserAndAssemblerStream()
    {
        const string request = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";

        var stream = new MemoryStream(Utils.StringToByteArray(request));
        var result = RadiusPacketParser.TryParsePacketFromStream(stream, out var packet, DefaultSecret);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.True);
            Assert.That(packet, Is.Not.Null);
        });

        var bytes = RadiusPacketParser.GetBytes(packet!, DefaultSecret);

        Assert.That(bytes.ToHexString(), Is.EqualTo(request));
    }


    /// <summary>
    /// Test parsing and rebuilding a packet
    /// </summary>
    [Obsolete("Parsing from stream is obsolete")]
    [TestCase]
    public void TestPacketParserAndAssemblerStreamExtraDataIgnored()
    {
        const string request =
            "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3ff00ff00ff00ff";
        const string expected = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";

        var stream = new MemoryStream(Utils.StringToByteArray(request));
        var result = RadiusPacketParser.TryParsePacketFromStream(stream, out var packet, DefaultSecret);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.True);
            Assert.That(packet, Is.Not.Null);
        });

        var bytes = RadiusPacketParser.GetBytes(packet!, DefaultSecret);

        Assert.That(bytes.ToHexString(), Is.EqualTo(expected));
    }


    /// <summary>
    /// Test parsing and rebuilding a packet
    /// </summary>
    [TestCase]
    public void TestPacketParserAndAssemblerExtraDataIgnored()
    {
        const string request =
            "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa300ff00ff00ff";
        const string expected = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";

        var requestPacket = RadiusPacketParser.Parse(Utils.StringToByteArray(request), DefaultSecret);
        var bytes = RadiusPacketParser.GetBytes(requestPacket, DefaultSecret);

        Assert.That(bytes.ToHexString(), Is.EqualTo(expected));
    }


    /// <summary>
    /// Test parsing packet with missing data
    /// </summary>
    [TestCase]
    public void TestPacketParserMissingData()
    {
        const string request = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84f";

        var radiusPacketParser = new RadiusPacketParser(NullLogger<RadiusPacketParser>.Instance, Dictionary);
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            radiusPacketParser.Parse(Utils.StringToByteArray(request), DefaultSecret));
    }


    /// <summary>
    /// Test parsing and rebuilding a packet
    /// </summary>
    [TestCase]
    public void TestCreatingAndParsingPacket()
    {
        var packet = new AccessRequest(1);
        packet.AddMessageAuthenticator();
        packet.AddAttribute("User-Name", "test@example.com");
        packet.AddAttribute("User-Password", "test");
        packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("127.0.0.1"));
        packet.AddAttribute("NAS-Port", 100);
        packet.AddAttribute("3GPP-IMSI-MCC-MNC", "24001");
        packet.AddAttribute("3GPP-CG-Address", IPAddress.Parse("127.0.0.1"));

        var testPacket = RadiusPacketParser.Parse(RadiusPacketParser.GetBytes(packet, DefaultSecret), DefaultSecret);

        Assert.Multiple(() =>
        {
            Assert.That(testPacket.GetAttribute<string>("User-Name"), Is.EqualTo("test@example.com"));
            Assert.That(testPacket.GetAttribute<string>("User-Password"), Is.EqualTo("test"));
            Assert.That(testPacket.GetAttribute<IPAddress>("NAS-IP-Address"), Is.EqualTo(IPAddress.Parse("127.0.0.1")));
            Assert.That(testPacket.GetAttributes<IPAddress>("NAS-IP-Address")
                    .First(),
                Is.EqualTo(IPAddress.Parse("127.0.0.1"))); // this should actually be tested with EAP-Message attributes
            Assert.That(testPacket.GetAttribute<uint>("NAS-Port"), Is.EqualTo(100));
            Assert.That(testPacket.GetAttribute<string>("3GPP-IMSI-MCC-MNC"), Is.EqualTo("24001"));
            Assert.That(testPacket.GetAttribute<IPAddress>("3GPP-CG-Address"),
                Is.EqualTo(IPAddress.Parse("127.0.0.1")));
        });
    }


    /// <summary>
    /// Test parsing and rebuilding a packet
    /// </summary>
    [TestCase]
    public void TestCreatingMissingAttributes()
    {
        var packet = new AccessRequest(1);
        packet.AddAttribute("User-Name", "test@example.com");
        packet.AddAttribute("User-Password", "test");

        var radiusPacketParser = new RadiusPacketParser(NullLogger<RadiusPacketParser>.Instance, Dictionary,
            skipBlastRadiusChecks: true);
        var testPacket = radiusPacketParser.Parse(radiusPacketParser.GetBytes(packet, DefaultSecret), DefaultSecret);

        Assert.Multiple(() =>
        {
            Assert.That(testPacket.GetAttribute<uint?>("NAS-Port"), Is.Null);
            Assert.That(testPacket.GetAttributes<uint>("NAS-Port"), Is.Empty);
        });
    }


    /// <summary>
    /// Test message authenticator validation success
    /// </summary>
    [TestCase]
    public void TestMessageAuthenticatorValidationSuccess()
    {
        const string request = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";

        Assert.DoesNotThrow(() => RadiusPacketParser.Parse(Utils.StringToByteArray(request), DefaultSecret));
    }


    /// <summary>
    /// Test message authenticator validation fail
    /// </summary>
    [TestCase]
    public void TestMessageAuthenticatorValidationFail()
    {
        const string request = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";
        const string secret = "xyzzy5461durr";

        Assert.Throws<InvalidMessageAuthenticatorException>(() =>
            RadiusPacketParser.Parse(Utils.StringToByteArray(request), Encoding.UTF8.GetBytes(secret)));
    }


    /// <summary>
    /// Create CoA request packet and verify bytes
    /// </summary>
    [TestCase]
    public void TestCreateCoARequestPacket()
    {
        const string expected = "2b0000266613591d86e32fa6dbae94f13772573601066e656d6f0406c0a80110050600000003";

        var packet = new CoaRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
        packet.AddAttribute("NAS-Port", 3);

        Assert.That(RadiusPacketParser.GetBytes(packet, DefaultSecret).ToHexString(),
            Is.EqualTo(expected));
    }


    /// <summary>
    /// Test message authenticator validation success with no side effect
    /// </summary>
    [TestCase]
    public void TestMessageAuthenticatorNoSideEffect()
    {
        var request =
            Utils.StringToByteArray("0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3");
        var expected =
            Utils.StringToByteArray("0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3");

        Assert.DoesNotThrow(() => RadiusPacketParser.Parse(request, DefaultSecret));
        Assert.That(request.ToHexString(), Is.EqualTo(expected.ToHexString()));
    }


    [TestCase]
    public void TestMessageAuthenticatorResponsePacket()
    {
        const string expected =
            "0368002c71624da25c0b5897f70539e019a81eae4f06046700045012ce70fe87a997b44de583cd19bea29321";
        var secret = "testing123"u8.ToArray();

        var requestAuthenticator = Utils.StringToByteArray("b3e22ff855a690280e6c3444c46e663b");
        var response = new AccessReject(104);

        response.AddAttribute("EAP-Message", Utils.StringToByteArray("04670004"));
        response.AddMessageAuthenticator();

        Assert.That(RadiusPacketParser.GetBytes(response, secret, requestAuthenticator).ToHexString(),
            Is.EqualTo(expected));
    }

    [TestCase]
    public void TestMessageAuthenticatorResponsePacketBlastRadius()
    {
        // access accept response packet
        var response =
            Utils.StringToByteArray("020000261b49188b89251f7c9b8604772ca685925012b02cae7428c0e4e2301c060a5bf75bff");

        // request authenticator from the corresponding request
        var requestAuthenticator = Utils.StringToByteArray("fb421846209424ca0982ad9326e5ccf0");

        Assert.DoesNotThrow(() => RadiusPacketParser.Parse(response, DefaultSecret, requestAuthenticator));
    }

    [TestCase]
    public void TestMessageAuthenticatorResponsePacketBlastRadiusMissingAuthenticator()
    {
        // access accept response packet
        var response =
            Utils.StringToByteArray(
                "010000380f403f9473978057bd83d5cb98f4227a01066e656d6f02120dbe708d93d413ce3196e43f782a0aee0406c0a80110050600000003");

        // request authenticator from the corresponding request
        var requestAuthenticator = Utils.StringToByteArray("fb421846209424ca0982ad9326e5ccf0");

        Assert.Throws<MissingMessageAuthenticatorException>(() =>
            RadiusPacketParser.Parse(response, DefaultSecret, requestAuthenticator));
    }

    /// <summary>
    /// Test vendor attribute parsing
    /// </summary>
    [TestCase]
    public void TestVendorSpecificAttribute()
    {
        // "3GPP-IMSI-MCC-MNC": "24001"
        var bytes = Utils.StringToByteArray("000028af08073234303031");

        var vsa = new VendorSpecificAttribute(bytes);

        Assert.Multiple(() =>
        {
            Assert.That(vsa.VendorId, Is.EqualTo(10415));
            Assert.That(vsa.VendorCode, Is.EqualTo(8));
            Assert.That(vsa.Value.ToHexString(), Is.EqualTo("3234303031"));
            Assert.That(vsa.Length, Is.EqualTo(7));
        });
    }


    [TestCase]
    public void CreatePacketWithEAPMessageValid()
    {
        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddMessageAuthenticator();
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("EAP-Message", new byte[10]);

        Assert.DoesNotThrow(() =>
            RadiusPacketParser.Parse(RadiusPacketParser.GetBytes(packet, DefaultSecret), DefaultSecret));
    }


    [TestCase]
    public void CreatePacketWithEAPMessageMissingMessageAuthenticator()
    {
        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("EAP-Message", new byte[10]);

        Assert.Throws<MissingMessageAuthenticatorException>(() => RadiusPacketParser.Parse(
            RadiusPacketParser.GetBytes(packet, DefaultSecret), DefaultSecret));
    }


    [TestCase]
    public void CreatePacketWithEAPMessageInvalidMessageAuthenticator()
    {
        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddMessageAuthenticator();
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("EAP-Message", new byte[10]);

        var bytes = RadiusPacketParser.GetBytes(packet, DefaultSecret);
        bytes[25] = 0; // Message-Authenticator is the first attribute here, so position 25 will be inside it

        Assert.Throws<InvalidMessageAuthenticatorException>(() => RadiusPacketParser.Parse(bytes, DefaultSecret));
    }

    [TestCase]
    public void CreatePacketOverPacketSizeLimit()
    {
        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddMessageAuthenticator();
        packet.AddAttribute("User-Name", "nemo");

        for (var i = 0; i < 40; i++)
        {
            packet.AddAttribute("EAP-Message", new byte[100]);
        }

        Assert.Throws<InvalidOperationException>(() => RadiusPacketParser.GetBytes(packet, DefaultSecret));
    }

    [TestCase]
    public void CreatePacketOverAttributeLimit()
    {
        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddMessageAuthenticator();
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("EAP-Message", new byte[253]); // packet header is 2 bytes, so this will be at the limit

        Assert.DoesNotThrow(() => RadiusPacketParser.GetBytes(packet, DefaultSecret));
    }

    [TestCase]
    public void CreatePacketOverAttributeSizeLimit()
    {
        var packet = new AccessRequest(0)
        {
            Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a")
        };
        packet.AddMessageAuthenticator();
        packet.AddAttribute("User-Name", "nemo");
        packet.AddAttribute("EAP-Message", new byte[254]); // packet header is 2 bytes, so this will be one above limit

        Assert.Throws<InvalidOperationException>(() => RadiusPacketParser.GetBytes(packet, DefaultSecret));
    }
}