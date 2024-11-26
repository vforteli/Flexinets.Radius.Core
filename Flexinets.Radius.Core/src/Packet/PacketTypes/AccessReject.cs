namespace Flexinets.Radius.Core.PacketTypes
{
    public class AccessReject : RadiusPacket
    {
        public AccessReject(byte identifier) : base(PacketCode.AccessReject, identifier)
        {
        }

        internal AccessReject()
        {
        }
    }
}