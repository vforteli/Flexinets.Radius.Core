using NUnit.Framework;
using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;

namespace Flexinets.Radius.Core.Tests
{
    [TestFixture]
    public class RadiusCoreTests
    {
        private RadiusDictionary GetDictionary()
        {
            var path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\content\\radius.dictionary";
            var dictionary = new RadiusDictionary(path);
            return dictionary;
        }


        /// <summary>
        /// Create packet and verify bytes
        /// Example from https://tools.ietf.org/html/rfc2865
        /// </summary>
        [TestCase]
        public void TestCreateAccessRequestPacket()
        {
            var expected = "010000380f403f9473978057bd83d5cb98f4227a01066e656d6f02120dbe708d93d413ce3196e43f782a0aee0406c0a80110050600000003";
            var secret = "xyzzy5461";

            var packet = new RadiusPacket(PacketCode.AccessRequest, 0, secret);
            packet.Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a");
            packet.AddAttribute("User-Name", "nemo");
            packet.AddAttribute("User-Password", "arctangent");
            packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
            packet.AddAttribute("NAS-Port", 3);

            Assert.AreEqual(expected, packet.GetBytes(GetDictionary()).ToHexString());
        }


        /// <summary>
        /// Create packet and verify bytes, including IPv6 attribute
        /// Example from https://tools.ietf.org/html/rfc2865
        /// </summary>
        [TestCase]
        public void TestCreateAccessRequestPacketIPv6()
        {
            var expected = IPAddress.IPv6Loopback;
            var secret = "xyzzy5461";

            var packet = new RadiusPacket(PacketCode.AccessRequest, 0, secret);
            packet.Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a");
            packet.AddAttribute("User-Name", "nemo");
            packet.AddAttribute("User-Password", "arctangent");
            packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
            packet.AddAttribute("Framed-IPv6-Address", expected);
            packet.AddAttribute("NAS-Port", 3);

            var actual = packet.GetAttribute<IPAddress>("Framed-IPv6-Address");
            Assert.AreEqual(expected, actual);
        }


        /// <summary>
        /// Create packet and verify bytes
        /// Example from https://tools.ietf.org/html/rfc2865
        /// </summary>
        [TestCase]
        public void TestCreateAccessRequestPacketUnknownAttribute()
        {
            var secret = "xyzzy5461";

            var packet = new RadiusPacket(PacketCode.AccessRequest, 0, secret);
            packet.Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a");
            packet.AddAttribute("User-Name", "nemo");
            packet.AddAttribute("hurr", "durr");
            packet.AddAttribute("User-Password", "arctangent");
            packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
            packet.AddAttribute("NAS-Port", 3);

            Assert.That(() => packet.GetBytes(GetDictionary()),
               Throws.TypeOf<InvalidOperationException>());
        }


        /// <summary>
        /// Create disconnect request packet and verify bytes
        /// </summary>
        [TestCase]
        public void TestCreateDisconnectRequestPacket()
        {
            var expected = "2801001e2ec8a0da729620319be0140bc28e92682c0a3039303432414638";
            var secret = "xyzzy5461";

            var packet = new RadiusPacket(PacketCode.DisconnectRequest, 1, secret);
            packet.AddAttribute("Acct-Session-Id", "09042AF8");

            Assert.AreEqual(expected, packet.GetBytes(GetDictionary()).ToHexString());
        }


        /// <summary>
        /// Create disconnect request packet and verify bytes
        /// </summary>
        [TestCase]
        public void TestCreateStatusServerRequestPacket()
        {
            var expected = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";
            var secret = "xyzzy5461";

            var packet = new RadiusPacket(PacketCode.StatusServer, 218, secret);
            packet.Authenticator = Utils.StringToByteArray("8a54f4686fb394c52866e302185d0623");

            Assert.AreEqual(expected, packet.GetBytes(GetDictionary()).ToHexString());
        }


        /// <summary>
        /// Create accounting request        
        /// </summary>
        [TestCase]
        public void TestCreateAndParseAccountingRequestPacket()
        {
            var secret = "xyzzy5461";
            var dictionary = GetDictionary();
            var packet = new RadiusPacket(PacketCode.AccountingRequest, 0, secret);
            packet.AddAttribute("User-Name", "nemo");
            packet.AddAttribute("Acct-Status-Type", 2);
            packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
            packet.AddAttribute("NAS-Port", 3);

            var bytes = packet.GetBytes(dictionary);
            var derp = RadiusPacket.Parse(bytes, dictionary, Encoding.UTF8.GetBytes(secret));

        }


        ///// <summary>
        ///// Create packet and verify bytes
        ///// Example from https://tools.ietf.org/html/rfc2865
        ///// </summary>
        [TestCase]
        public void TestAccountingPacketRequestAuthenticatorSuccess()
        {
            var packetBytes = "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234";
            var secret = "xyzzy5461";

            var requestAuthenticator = RadiusPacket.CalculateRequestAuthenticator(Encoding.UTF8.GetBytes(secret), Utils.StringToByteArray(packetBytes));
            var packet = RadiusPacket.Parse(Utils.StringToByteArray(packetBytes), GetDictionary(), Encoding.UTF8.GetBytes(secret));

            Assert.AreEqual(packet.Authenticator.ToHexString(), requestAuthenticator.ToHexString());
        }


        ///// <summary>
        ///// Create packet and verify bytes
        ///// Example from https://tools.ietf.org/html/rfc2865
        ///// </summary>
        [TestCase]
        public void TestAccountingPacketRequestAuthenticatorFail()
        {
            var packetBytes = "0404002711019c27d4e00cbc523b3e2fc834baf401066e656d6f2806000000012c073230303234";
            var secret = "foo";

            var requestAuthenticator = RadiusPacket.CalculateRequestAuthenticator(Encoding.UTF8.GetBytes(secret), Utils.StringToByteArray(packetBytes));
            Assert.That(() => RadiusPacket.Parse(Utils.StringToByteArray(packetBytes), GetDictionary(), Encoding.UTF8.GetBytes(secret)),
                Throws.TypeOf<InvalidOperationException>());
        }


        /// <summary>
        /// Test parsing and rebuilding a packet
        /// </summary>
        [TestCase]
        public void TestPacketParserAndAssembler()
        {
            var request = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";
            var expected = request;
            var secret = "xyzzy5461";

            var dictionary = GetDictionary();
            var requestPacket = RadiusPacket.Parse(Utils.StringToByteArray(request), dictionary, Encoding.UTF8.GetBytes(secret));
            var bytes = requestPacket.GetBytes(dictionary);

            Assert.AreEqual(expected, bytes.ToHexString());
        }


        /// <summary>
        /// Test parsing and rebuilding a packet
        /// </summary>
        [TestCase]
        public void TestCreatingAndParsingPacket()
        {
            var secret = "xyzzy5461";

            var dictionary = GetDictionary();

            var packet = new RadiusPacket(PacketCode.AccessRequest, 1, secret);
            packet.AddAttribute("User-Name", "test@example.com");
            packet.AddAttribute("User-Password", "test");
            packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("127.0.0.1"));
            packet.AddAttribute("NAS-Port", 100);
            packet.AddAttribute("3GPP-IMSI-MCC-MNC", "24001");
            packet.AddAttribute("3GPP-CG-Address", IPAddress.Parse("127.0.0.1"));

            var testPacket = RadiusPacket.Parse(packet.GetBytes(dictionary), dictionary, Encoding.UTF8.GetBytes(secret));

            Assert.AreEqual("test@example.com", testPacket.GetAttribute<String>("User-Name"));
            Assert.AreEqual("test", testPacket.GetAttribute<String>("User-Password"));
            Assert.AreEqual(IPAddress.Parse("127.0.0.1"), testPacket.GetAttribute<IPAddress>("NAS-IP-Address"));
            Assert.AreEqual(100, testPacket.GetAttribute<UInt32>("NAS-Port"));
            Assert.AreEqual("24001", testPacket.GetAttribute<String>("3GPP-IMSI-MCC-MNC"));
            Assert.AreEqual(IPAddress.Parse("127.0.0.1"), testPacket.GetAttribute<IPAddress>("3GPP-CG-Address"));
        }


        /// <summary>
        /// Test message authenticator validation success
        /// </summary>
        [TestCase]
        public void TestMessageAuthenticatorValidationSuccess()
        {
            var request = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";
            var secret = "xyzzy5461";

            var dictionary = GetDictionary();
            var requestPacket = RadiusPacket.Parse(Utils.StringToByteArray(request), dictionary, Encoding.UTF8.GetBytes(secret));
        }


        /// <summary>
        /// Test message authenticator validation fail
        /// </summary>
        [TestCase]
        public void TestMessageAuthenticatorValidationFail()
        {
            var request = "0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3";
            var secret = "xyzzy5461durr";

            var dictionary = GetDictionary();
            Assert.That(() => RadiusPacket.Parse(Utils.StringToByteArray(request), dictionary, Encoding.UTF8.GetBytes(secret)),
              Throws.TypeOf<InvalidOperationException>());
        }


        /// <summary>
        /// Test passwords with length > 16        
        /// </summary>
        [TestCase("123456789")]
        [TestCase("12345678901234567890")]
        public void TestPasswordEncryptDecrypt(String password)
        {
            var secret = "xyzzy5461";
            var authenticator = "1234567890123456";

            var encrypted = RadiusPassword.Encrypt(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(authenticator), Encoding.UTF8.GetBytes(password));

            var decrypted = RadiusPassword.Decrypt(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(authenticator), encrypted);


            Assert.AreEqual(password, decrypted);
        }


        /// <summary>
        /// Create CoA request packet and verify bytes
        /// </summary>
        [TestCase]
        public void TestCreateCoARequestPacket()
        {
            var expected = "2b0000266613591d86e32fa6dbae94f13772573601066e656d6f0406c0a80110050600000003";
            var secret = "xyzzy5461";

            var packet = new RadiusPacket(PacketCode.CoaRequest, 0, secret);
            packet.Authenticator = Utils.StringToByteArray("0f403f9473978057bd83d5cb98f4227a");
            packet.AddAttribute("User-Name", "nemo");
            packet.AddAttribute("NAS-IP-Address", IPAddress.Parse("192.168.1.16"));
            packet.AddAttribute("NAS-Port", 3);
            Assert.AreEqual(expected, packet.GetBytes(GetDictionary()).ToHexString());
        }


        /// <summary>
        /// Test message authenticator validation success with no side effect
        /// </summary>
        [TestCase]
        public void TestMessageAuthenticatorNoSideEffect()
        {
            var request = Utils.StringToByteArray("0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3");
            var expected = Utils.StringToByteArray("0cda00268a54f4686fb394c52866e302185d062350125a665e2e1e8411f3e243822097c84fa3");
            var secret = "xyzzy5461";

            var dictionary = GetDictionary();
            var requestPacket = RadiusPacket.Parse(request, dictionary, Encoding.UTF8.GetBytes(secret));
            Assert.AreEqual(Utils.ToHexString(expected), Utils.ToHexString(request));
        }
    }
}
