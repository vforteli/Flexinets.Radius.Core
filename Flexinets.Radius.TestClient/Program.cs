using System.Net;
using System.Text;
using Flexinets.Radius;
using Flexinets.Radius.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;


var loggerFactory = LoggerFactory.Create(o =>
{
    o.AddSimpleConsole(c => c.SingleLine = true);
    o.SetMinimumLevel(LogLevel.Trace);
});

var logger = loggerFactory.CreateLogger("Flexinets.Radius.TestClient");

var dictionaryStream = new MemoryStream(Encoding.UTF8.GetBytes(TestDictionary.RadiusDictionary));
var dictionary = new RadiusDictionary(dictionaryStream, loggerFactory.CreateLogger<RadiusDictionary>());
var radiusPacketParser = new RadiusPacketParser(loggerFactory.CreateLogger<RadiusPacketParser>(), dictionary);

using var client = new RadiusClient(new IPEndPoint(IPAddress.Any, 58733), radiusPacketParser);


var packet = new RadiusPacket(PacketCode.AccessRequest, 0, "xyzzy5461");
packet.AddMessageAuthenticator();
packet.AddAttribute("User-Name", "nemo");
packet.AddAttribute("User-Password", "arctangent");

logger.LogInformation("Sending packet...");
var responsePacket = await client.SendPacketAsync(packet, new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1812),
    TimeSpan.FromSeconds(3));
if (responsePacket.Code == PacketCode.AccessAccept)
{
    // Hooray  
    Console.WriteLine("Access accepted!");
}