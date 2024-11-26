using Flexinets.Radius.Core;

namespace Flexinets.Radius;

public interface IPacketHandler : IDisposable
{
    Task<IRadiusPacket?> HandlePacketAsync(IRadiusPacket packet);
}