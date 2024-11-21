using System.Net;
using System.Text;
using Flexinets.Net;
using Flexinets.Radius;
using Flexinets.Radius.Core;
using Microsoft.Extensions.Logging;

var loggerFactory = LoggerFactory.Create(o =>
{
    o.AddSimpleConsole(c => c.SingleLine = true);
    o.SetMinimumLevel(LogLevel.Trace);
});

var dictionaryStream = new MemoryStream(Encoding.UTF8.GetBytes(TestDictionary.RadiusDictionary));
var dictionary = new RadiusDictionary(dictionaryStream, loggerFactory.CreateLogger<RadiusDictionary>());
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