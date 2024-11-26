namespace Flexinets.Radius.Core.PacketTypes
{
    public class CoaNak : RadiusPacket
    {
        public CoaNak(byte identifier) : base(PacketCode.CoaNak, identifier)
        {
        }

        internal CoaNak()
        {
        }
    }
}