using System.Net;
using System.Text;
using Flexinets.Radius;
using Flexinets.Radius.Core;
using Microsoft.Extensions.Logging;


var loggerFactory = LoggerFactory.Create(o =>
{
    o.AddSimpleConsole(c => c.SingleLine = true);
    o.SetMinimumLevel(LogLevel.Trace);
});

var logger = loggerFactory.CreateLogger(nameof(Program));

using var client = new RadiusClient(
    new IPEndPoint(IPAddress.Any, 0),
    new RadiusPacketParser(
        loggerFactory.CreateLogger<RadiusPacketParser>(),
        RadiusDictionary.Parse(DefaultDictionary.RadiusDictionary)));


var sharedSecret = Encoding.UTF8.GetBytes("xyzzy5461");
var requestPacket = new RadiusPacket(PacketCode.AccessRequest, 0);
requestPacket.AddMessageAuthenticator(); // Add message authenticator for blast radius
requestPacket.AddAttribute("User-Name", "nemo");
requestPacket.AddAttribute("User-Password", "arctangent");

logger.LogInformation("Sending packet...");

var responsePacket = await client.SendPacketAsync(
    requestPacket,
    sharedSecret,
    new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1812));

if (responsePacket.Code == PacketCode.AccessAccept)
{
    // Hooray  
    logger.LogInformation("Access accepted \\o/");
    logger.LogDebug(Utils.GetPacketString(responsePacket));
}