namespace Flexinets.Radius.Core.PacketTypes
{
    public class AccessRequest : RadiusPacket
    {
        public AccessRequest(byte identifier) : base(PacketCode.AccessRequest, identifier)
        {
        }

        internal AccessRequest()
        {
        }
    }
}