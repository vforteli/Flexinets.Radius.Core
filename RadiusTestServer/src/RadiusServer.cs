using Flexinets.Net;
using Flexinets.Radius.Core;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace Flexinets.Radius;

public enum RadiusServerType
{
    Authentication,
    Accounting
}

public class RadiusServer(
    IUdpClientFactory udpClientFactory,
    IPEndPoint localEndpoint,
    IRadiusPacketParser radiusPacketParser,
    RadiusServerType serverType,
    IPacketHandlerRepository packetHandlerRepository,
    ILogger<RadiusServer> logger) : IDisposable
{
    private IUdpClient? _server;

    public Boolean Running { get; private set; }


    /// <summary>
    /// Start listening for requests
    /// </summary>
    public void Start()
    {
        if (!Running)
        {
            _server = udpClientFactory.CreateClient(localEndpoint);
            Running = true;
            logger.LogInformation($"Starting Radius server on {localEndpoint}");
            _ = StartReceiveLoopAsync();
            logger.LogInformation("Server started");
        }
        else
        {
            logger.LogWarning("Server already started");
        }
    }


    /// <summary>
    /// Stop listening
    /// </summary>
    public void Stop()
    {
        if (Running)
        {
            logger.LogInformation("Stopping server");
            Running = false;
            _server?.Dispose();
            logger.LogInformation("Stopped");
        }
        else
        {
            logger.LogWarning("Server already stopped");
        }
    }


    /// <summary>
    /// Start the loop used for receiving packets
    /// </summary>
    private async Task StartReceiveLoopAsync()
    {
        while (Running)
        {
            try
            {
                if (_server == null)
                {
                    break;
                }

                var response = await _server.ReceiveAsync();
                _ = Task.Factory.StartNew(() => HandlePacket(response.RemoteEndPoint, response.Buffer),
                    TaskCreationOptions.LongRunning);
            }
            catch (ObjectDisposedException)
            {
            } // This is thrown when udpclient is disposed, can be safely ignored
            catch (Exception ex)
            {
                logger.LogCritical(ex, "Something went wrong receiving packet");
            }
        }
    }


    /// <summary>
    /// Used to handle the packets asynchronously
    /// </summary>
    private void HandlePacket(IPEndPoint remoteEndpoint, byte[] packetBytes)
    {
        try
        {
            logger.LogDebug($"Received packet from {remoteEndpoint}");

            if (packetHandlerRepository.TryGetHandler(remoteEndpoint.Address, out var handler))
            {
                var responsePacket = GetResponsePacket(handler.packetHandler, handler.sharedSecret, packetBytes,
                    remoteEndpoint);
                if (responsePacket != null)
                {
                    SendResponsePacket(responsePacket, remoteEndpoint);
                }
            }
            else
            {
                logger.LogError($"No packet handler found for remote ip {remoteEndpoint}");
                var packet = radiusPacketParser.Parse(packetBytes, Encoding.UTF8.GetBytes("wut"));
                DumpPacket(packet);
            }
        }
        catch (Exception ex) when (ex is ArgumentException || ex is OverflowException)
        {
            logger.LogWarning($"Ignoring malformed(?) packet received from {remoteEndpoint}", ex);
            logger.LogDebug(packetBytes.ToHexString());
        }
        catch (Exception ex)
        {
            logger.LogError(ex, $"Failed to receive packet from {remoteEndpoint}");
            logger.LogDebug(packetBytes.ToHexString());
        }
    }


    /// <summary>
    /// Parses a packet and gets a response packet from the handler
    /// </summary>
    internal IRadiusPacket? GetResponsePacket(
        IPacketHandler packetHandler,
        string sharedSecret,
        byte[] packetBytes,
        IPEndPoint remoteEndpoint)
    {
        var requestPacket = radiusPacketParser.Parse(packetBytes, Encoding.UTF8.GetBytes(sharedSecret));
        logger.LogInformation("Received {code} from {endpoint} Id={identifier}", requestPacket.Code, remoteEndpoint,
            requestPacket.Identifier);

        if (logger.IsEnabled(LogLevel.Debug))
        {
            DumpPacket(requestPacket);
        }

        logger.LogDebug(packetBytes.ToHexString());

        // Handle status server requests in server outside packet handler
        if (requestPacket.Code == PacketCode.StatusServer)
        {
            var responseCode = serverType == RadiusServerType.Authentication
                ? PacketCode.AccessAccept
                : PacketCode.AccountingResponse;

            logger.LogDebug($"Sending {responseCode} for StatusServer request from {remoteEndpoint}");
            return requestPacket.CreateResponsePacket(responseCode);
        }

        logger.LogDebug($"Handling packet for remote ip {remoteEndpoint.Address} with {packetHandler.GetType()}");

        var sw = Stopwatch.StartNew();
        var responsePacket = packetHandler.HandlePacket(requestPacket);

        logger.LogDebug(
            $"{remoteEndpoint} Id={responsePacket.Identifier}, Received {responsePacket.Code} from handler in {sw.ElapsedMilliseconds}ms");

        if (requestPacket.Attributes.ContainsKey("Proxy-State"))
        {
            responsePacket.Attributes.Add("Proxy-State",
                requestPacket.Attributes.SingleOrDefault(o => o.Key == "Proxy-State").Value);
        }

        return responsePacket;
    }


    /// <summary>
    /// Sends a packet
    /// </summary>
    private void SendResponsePacket(IRadiusPacket responsePacket, IPEndPoint remoteEndpoint)
    {
        var responseBytes = radiusPacketParser.GetBytes(responsePacket);
        _server?.Send(responseBytes, responseBytes.Length, remoteEndpoint);
        logger.LogInformation($"{responsePacket.Code} sent to {remoteEndpoint} Id={responsePacket.Identifier}");
    }


    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
        _server?.Dispose();
    }


    /// <summary>
    /// Dump the packet attributes to the log
    /// </summary>
    private void DumpPacket(IRadiusPacket packet)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Packet dump for {packet.Identifier}:");
        foreach (var attribute in packet.Attributes)
        {
            if (attribute.Key == "User-Password")
            {
                sb.AppendLine($"{attribute.Key} length : {attribute.Value.First().ToString()?.Length}");
            }
            else
            {
                attribute.Value.ForEach(o => sb.AppendLine($"{attribute.Key} : {o} [{o.GetType()}]"));
            }
        }

        logger.LogDebug(sb.ToString());
    }
}