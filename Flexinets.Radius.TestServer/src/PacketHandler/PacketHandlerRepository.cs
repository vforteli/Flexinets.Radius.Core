using System.Net;

namespace Flexinets.Radius;

public class PacketHandlerRepository : IPacketHandlerRepository
{
    private readonly Dictionary<IPAddress, (IPacketHandler packetHandler, byte[] secret)> _packetHandlerAddresses =
        new();

    private readonly Dictionary<IPNetwork, (IPacketHandler packetHandler, byte[] secret)>
        _packetHandlerNetworks = new();

    /// <summary>
    /// Add packet handler for remote endpoint
    /// </summary>
    public void AddPacketHandler(IPAddress remoteAddress, IPacketHandler packetHandler, byte[] sharedSecret)
    {
        _packetHandlerAddresses.Add(remoteAddress, (packetHandler, sharedSecret));
    }


    /// <summary>
    /// Add packet handler for multiple remote endpoints
    /// </summary>
    public void AddPacketHandler(List<IPAddress> remoteAddresses, IPacketHandler packetHandler, byte[] sharedSecret)
    {
        foreach (var remoteAddress in remoteAddresses)
        {
            _packetHandlerAddresses.Add(remoteAddress, (packetHandler, sharedSecret));
        }
    }


    /// <summary>
    /// Add packet handler for IP range
    /// </summary>
    public void Add(IPNetwork remoteAddressRange, IPacketHandler packetHandler, byte[] sharedSecret)
    {
        _packetHandlerNetworks.Add(remoteAddressRange, (packetHandler, sharedSecret));
    }


    /// <summary>
    /// Try to find a packet handler for remote address
    /// </summary>
    public bool TryGetHandler(IPAddress remoteAddress, out (IPacketHandler packetHandler, byte[] sharedSecret) handler)
    {
        if (_packetHandlerAddresses.TryGetValue(remoteAddress, out handler))
        {
            return true;
        }

        if (_packetHandlerNetworks.Any(o => o.Key.Contains(remoteAddress)))
        {
            handler = _packetHandlerNetworks.FirstOrDefault(o => o.Key.Contains(remoteAddress)).Value;
            return true;
        }

        return _packetHandlerAddresses.TryGetValue(IPAddress.Any, out handler);
    }
}