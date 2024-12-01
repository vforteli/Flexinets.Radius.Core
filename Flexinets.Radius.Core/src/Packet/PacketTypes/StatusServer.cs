using System.Security.Cryptography;

namespace Flexinets.Radius.Core.PacketTypes
{
    public class StatusServer : RadiusPacket
    {
        public StatusServer(byte identifier) : base(PacketCode.StatusServer, identifier)
        {
            RandomNumberGenerator.Fill(Authenticator);
            AddMessageAuthenticator(); // todo this is a bit sus... the message-authenticator isnt added automatically to other packets
        }
        
        internal StatusServer()
        {
        }
    }
}