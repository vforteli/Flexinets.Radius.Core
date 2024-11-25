using System;
using System.IO;

namespace Flexinets.Radius.Core
{
    public interface IRadiusPacketParser
    {
        byte[] GetBytes(IRadiusPacket packet);
        IRadiusPacket Parse(byte[] packetBytes, byte[] sharedSecret, byte[] requestAuthenticator = null);
        
        [Obsolete("Use parse instead... this isnt async anyway")]
        bool TryParsePacketFromStream(Stream stream, out IRadiusPacket packet, byte[] sharedSecret, byte[] requestAuthenticator = null);
    }
}