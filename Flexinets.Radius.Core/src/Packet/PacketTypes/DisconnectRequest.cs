namespace Flexinets.Radius.Core.PacketTypes
{
    public class DisconnectRequest : RadiusPacket
    {
        public DisconnectRequest(byte identifier) : base(PacketCode.DisconnectRequest, identifier)
        {
        }

        internal DisconnectRequest()
        {
        }
    }
}