namespace Flexinets.Radius.Core.PacketTypes
{
    public class AccessChallenge : RadiusPacket
    {
        public AccessChallenge(byte identifier) : base(PacketCode.AccessChallenge, identifier)
        {
        }

        internal AccessChallenge()
        {
        }
    }
}