namespace Flexinets.Radius.Core.PacketTypes
{
    public class StatusClient : RadiusPacket
    {
        public StatusClient(byte identifier) : base(PacketCode.StatusClient, identifier)
        {
        }

        internal StatusClient()
        {
        }
    }
}