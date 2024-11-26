using System.Net;

namespace Flexinets.Radius;

public interface IPacketHandlerRepository
{
    bool TryGetHandler(IPAddress remoteAddress, out (IPacketHandler packetHandler, byte[] sharedSecret) handler);
}