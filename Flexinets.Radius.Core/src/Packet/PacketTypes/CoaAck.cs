namespace Flexinets.Radius.Core.PacketTypes
{
    public class CoaAck : RadiusPacket
    {
        public CoaAck(byte identifier) : base(PacketCode.CoaAck, identifier)
        {
        }

        internal CoaAck()
        {
        }
    }
}