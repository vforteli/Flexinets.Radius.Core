using System;
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace Flexinets.Radius.Core
{
    public partial class RadiusPacketParser
    {
        /// <summary>
        /// Tries to get a packet from the stream. Returns true if successful
        /// Returns false if no packet could be parsed or stream is empty ie closing
        /// </summary>
        [Obsolete("Use parse instead... this isnt async anyway")]
        public bool TryParsePacketFromStream(
            Stream stream,
            out IRadiusPacket? packet,
            byte[] sharedSecret,
            byte[]? requestAuthenticator = null)
        {
            var packetHeaderBytes = new byte[4];
            var i = stream.Read(packetHeaderBytes, 0, 4);
            if (i != 0)
            {
                try
                {
                    var packetLength = BitConverter.ToUInt16(packetHeaderBytes.Reverse().ToArray(), 0);
                    var packetContentBytes = new byte[packetLength - 4];
                    stream.Read(packetContentBytes, 0,
                        packetContentBytes
                            .Length); // todo stream.read should use loop in case everything is not available immediately

                    packet = Parse(packetHeaderBytes.Concat(packetContentBytes).ToArray(), sharedSecret,
                        requestAuthenticator);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Unable to parse packet from stream");
                }
            }

            packet = null;
            return false;
        }
    }
}