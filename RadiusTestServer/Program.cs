using System.Net;
using Flexinets.Net;
using Flexinets.Radius;
using Flexinets.Radius.Core;
using Microsoft.Extensions.Logging;

var loggerFactory = LoggerFactory.Create(o =>
{
    o.AddSimpleConsole(c => c.SingleLine = true);
    o.SetMinimumLevel(LogLevel.Trace);
});

var dictionary = RadiusDictionary.Parse(DefaultDictionary.RadiusDictionary);
var handlerRepository = new PacketHandlerRepository();
handlerRepository.AddPacketHandler(IPAddress.Any, new TestPacketHandler(), "somesecret");

var server = new RadiusServer(
    new UdpClientFactory(),
    new IPEndPoint(IPAddress.Any, 1812),
    new RadiusPacketParser(loggerFactory.CreateLogger<RadiusPacketParser>(), dictionary),
    RadiusServerType.Authentication,
    handlerRepository,
    loggerFactory.CreateLogger<RadiusServer>());


server.Start();

Console.WriteLine("Press any key to stop...");
Console.ReadKey();
Console.WriteLine("Stopping...");