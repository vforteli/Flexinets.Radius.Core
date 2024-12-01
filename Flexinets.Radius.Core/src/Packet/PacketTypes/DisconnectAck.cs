namespace Flexinets.Radius.Core.PacketTypes
{
    public class DisconnectAck : RadiusPacket
    {
        public DisconnectAck(byte identifier) : base(PacketCode.DisconnectAck, identifier)
        {
        }

        internal DisconnectAck()
        {
        }
    }
}