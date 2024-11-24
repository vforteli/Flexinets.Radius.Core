using Flexinets.Net;
using Flexinets.Radius.Core;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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
    private IUdpClient? _udpClient;


    /// <summary>
    /// Start listening for requests
    /// </summary>
    public void Start()
    {
        if (_udpClient == null)
        {
            _udpClient = udpClientFactory.CreateClient(localEndpoint);
            logger.LogInformation("Starting Radius server on {localEndpoint}", localEndpoint);
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
        if (_udpClient != null)
        {
            logger.LogInformation("Stopping server");
            _udpClient.Dispose();
            _udpClient = null;
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
        while (_udpClient != null)
        {
            try
            {
                var response = await _udpClient.ReceiveAsync();
                _ = Task.Factory.StartNew(() => HandlePacket(response.RemoteEndPoint, response.Buffer),
                    TaskCreationOptions.LongRunning);
            }
            catch (ObjectDisposedException) // This is thrown when udpclient is disposed, can be safely ignored
            {
            }
            catch (SocketException ex) when (ex.ErrorCode == 89)
            {
            }
            catch (Exception ex)
            {
                logger.LogCritical(ex, "Something went wrong receiving packet");
            }
        }
    }


    /// <summary>
    /// Used to handle the packets asynchronously
    /// </summary>
    private async Task HandlePacket(IPEndPoint remoteEndpoint, byte[] packetBytes)
    {
        try
        {
            logger.LogDebug("Received packet from {remoteEndpoint}", remoteEndpoint);

            if (packetHandlerRepository.TryGetHandler(remoteEndpoint.Address, out var handler))
            {
                var responsePacket = GetResponsePacket(handler.packetHandler, handler.sharedSecret, packetBytes,
                    remoteEndpoint);

                if (responsePacket != null)
                {
                    await SendResponsePacketAsync(responsePacket, remoteEndpoint);
                }
            }
            else
            {
                logger.LogError("No packet handler found for remote ip {remoteEndpoint}", remoteEndpoint);

                if (logger.IsEnabled(LogLevel.Debug))
                {
                    // no handler found, but dump the raw packet with some secret
                    logger.LogDebug(
                        Utils.GetPacketString(radiusPacketParser.Parse(packetBytes, Encoding.UTF8.GetBytes("wut"))));
                }
            }
        }
        catch (Exception ex) when (ex is ArgumentException or OverflowException)
        {
            logger.LogWarning(ex, "Ignoring malformed(?) packet received from {remoteEndpoint}", remoteEndpoint);
            logger.LogDebug(packetBytes.ToHexString());
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to receive packet from {remoteEndpoint}", remoteEndpoint);
            logger.LogDebug(packetBytes.ToHexString());
        }
    }


    /// <summary>
    /// Parses a packet and gets a response packet from the handler
    /// </summary>
    private IRadiusPacket? GetResponsePacket(
        IPacketHandler packetHandler,
        string sharedSecret,
        byte[] packetBytes,
        IPEndPoint remoteEndpoint)
    {
        var requestPacket = radiusPacketParser.Parse(packetBytes, Encoding.UTF8.GetBytes(sharedSecret));
        logger.LogInformation("Received {code} from {endpoint} Id={identifier}",
            requestPacket.Code, remoteEndpoint, requestPacket.Identifier);

        if (logger.IsEnabled(LogLevel.Debug))
        {
            logger.LogDebug(Utils.GetPacketString(requestPacket));
            logger.LogDebug(packetBytes.ToHexString());
        }

        // Handle status server requests in server outside packet handler
        if (requestPacket.Code == PacketCode.StatusServer)
        {
            var responseCode = serverType == RadiusServerType.Authentication
                ? PacketCode.AccessAccept
                : PacketCode.AccountingResponse;

            logger.LogDebug("Sending {responseCode} for StatusServer request from {remoteEndpoint}",
                responseCode, remoteEndpoint);

            return requestPacket.CreateResponsePacket(responseCode);
        }

        logger.LogDebug("Handling packet for remote ip {remoteEndpoint.Address} with {packetHandler.GetType()}",
            remoteEndpoint.Address, packetHandler.GetType());

        var sw = Stopwatch.StartNew();
        var responsePacket = packetHandler.HandlePacket(requestPacket);

        if (responsePacket == null)
        {
            logger.LogInformation("Handler declined to respond");
            return null;
        }

        logger.LogDebug(
            "{remoteEndpoint} Id={responsePacket.Identifier}, Received {response.PacketCode} from handler in {sw.ElapsedMilliseconds}ms",
            remoteEndpoint, responsePacket.Identifier, responsePacket.Code, sw.ElapsedMilliseconds);

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
    private async Task SendResponsePacketAsync(IRadiusPacket responsePacket, IPEndPoint remoteEndpoint)
    {
        ArgumentNullException.ThrowIfNull(_udpClient);

        var responseBytes = radiusPacketParser.GetBytes(responsePacket);
        await _udpClient.SendAsync(responseBytes, responseBytes.Length, remoteEndpoint);

        logger.LogInformation("{responsePacket.Code} sent to {remoteEndpoint} Id={responsePacket.Identifier}",
            responsePacket.Code, remoteEndpoint, responsePacket.Identifier);
    }


    /// <summary>
    /// Dispose
    /// </summary>
    public void Dispose()
    {
        GC.SuppressFinalize(this);
        _udpClient?.Dispose();
    }
}