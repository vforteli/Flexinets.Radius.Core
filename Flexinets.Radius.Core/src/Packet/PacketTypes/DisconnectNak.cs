namespace Flexinets.Radius.Core.PacketTypes
{
    public class DisconnectNak : RadiusPacket
    {
        public DisconnectNak(byte identifier) : base(PacketCode.DisconnectNak, identifier)
        {
        }

        internal DisconnectNak()
        {
        }
    }
}