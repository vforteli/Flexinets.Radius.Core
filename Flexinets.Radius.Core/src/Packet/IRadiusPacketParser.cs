﻿using System.IO;

namespace Flexinets.Radius.Core
{
    public interface IRadiusPacketParser
    {
        byte[] GetBytes(IRadiusPacket packet);
        IRadiusPacket Parse(byte[] packetBytes, byte[] sharedSecret, byte[]? requestAuthenticator = null);
        bool TryParsePacketFromStream(Stream stream, out IRadiusPacket? packet, byte[] sharedSecret, byte[]? requestAuthenticator = null);
    }
}