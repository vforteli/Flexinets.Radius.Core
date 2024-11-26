using System.Security.Cryptography;

namespace Flexinets.Radius.Core.PacketTypes
{
    public class AccessAccept : RadiusPacket
    {
        public AccessAccept(byte identifier) : base(PacketCode.AccessAccept, identifier)
        {
            RandomNumberGenerator.Fill(Authenticator);
        }

        internal AccessAccept()
        {
        }
    }
}