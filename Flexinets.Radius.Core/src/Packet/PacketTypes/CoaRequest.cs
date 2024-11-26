namespace Flexinets.Radius.Core.PacketTypes
{
    public class CoaRequest : RadiusPacket
    {
        public CoaRequest(byte identifier) : base(PacketCode.CoaRequest, identifier)
        {
        }

        internal CoaRequest()
        {
        }
    }
}