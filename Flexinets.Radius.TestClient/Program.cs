using System.Net;
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
    new IPEndPoint(IPAddress.Any, 58733),
    new RadiusPacketParser(
        loggerFactory.CreateLogger<RadiusPacketParser>(),
        RadiusDictionary.Parse(DefaultDictionary.RadiusDictionary)));


var requestPacket = new RadiusPacket(PacketCode.AccessRequest, 0, "xyzzy5461");
requestPacket.AddMessageAuthenticator(); // Add message authenticator for blast radius
requestPacket.AddAttribute("User-Name", "nemo");
requestPacket.AddAttribute("User-Password", "arctangent");

logger.LogInformation("Sending packet...");

var responsePacket = await client.SendPacketAsync(
    requestPacket,
    new IPEndPoint(IPAddress.Parse("127.0.0.1"), 1812));

if (responsePacket.Code == PacketCode.AccessAccept)
{
    // Hooray  
    logger.LogInformation("Access accepted \\o/");
    logger.LogDebug(Utils.GetPacketString(responsePacket));
}