using Flexinets.Radius.Core;
using System;

namespace Flexinets.Radius.Core
{
    public interface IPacketHandler : IDisposable
    {
        IRadiusPacket HandlePacket(IRadiusPacket packet);
    }
}
