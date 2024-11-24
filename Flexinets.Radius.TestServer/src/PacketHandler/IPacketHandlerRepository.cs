using System.Net;
using Flexinets.Radius.Core;

namespace Flexinets.Radius;

public interface IPacketHandlerRepository
{
    bool TryGetHandler(IPAddress remoteAddress, out (IPacketHandler packetHandler, string sharedSecret) handler);
}