namespace Flexinets.Radius.Core.PacketTypes
{
    public class AccountingRequest : RadiusPacket
    {
        public AccountingRequest(byte identifier) : base(PacketCode.AccountingRequest, identifier)
        {
        }

        internal AccountingRequest()
        {
        }
    }
}