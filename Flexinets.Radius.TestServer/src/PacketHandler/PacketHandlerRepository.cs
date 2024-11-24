using Flexinets.Radius.Core;
using System.Net;

namespace Flexinets.Radius;

public class PacketHandlerRepository : IPacketHandlerRepository
{
    private readonly Dictionary<IPAddress, (IPacketHandler packetHandler, string secret)> _packetHandlerAddresses =
        new();

    private readonly Dictionary<IPNetwork, (IPacketHandler packetHandler, string secret)>
        _packetHandlerNetworks = new();

    /// <summary>
    /// Add packet handler for remote endpoint
    /// </summary>
    public void AddPacketHandler(IPAddress remoteAddress, IPacketHandler packetHandler, string sharedSecret)
    {
        _packetHandlerAddresses.Add(remoteAddress, (packetHandler, sharedSecret));
    }


    /// <summary>
    /// Add packet handler for multiple remote endpoints
    /// </summary>
    public void AddPacketHandler(List<IPAddress> remoteAddresses, IPacketHandler packetHandler, string sharedSecret)
    {
        foreach (var remoteAddress in remoteAddresses)
        {
            _packetHandlerAddresses.Add(remoteAddress, (packetHandler, sharedSecret));
        }
    }


    /// <summary>
    /// Add packet handler for IP range
    /// </summary>
    public void Add(IPNetwork remoteAddressRange, IPacketHandler packetHandler, String sharedSecret)
    {
        _packetHandlerNetworks.Add(remoteAddressRange, (packetHandler, sharedSecret));
    }


    /// <summary>
    /// Try to find a packet handler for remote address
    /// </summary>
    public bool TryGetHandler(IPAddress remoteAddress, out (IPacketHandler packetHandler, string sharedSecret) handler)
    {
        if (_packetHandlerAddresses.TryGetValue(remoteAddress, out handler))
        {
            return true;
        }
        else if (_packetHandlerNetworks.Any(o => o.Key.Contains(remoteAddress)))
        {
            handler = _packetHandlerNetworks.FirstOrDefault(o => o.Key.Contains(remoteAddress)).Value;
            return true;
        }
        else if (_packetHandlerAddresses.TryGetValue(IPAddress.Any, out handler))
        {
            return true;
        }

        return false;
    }
}