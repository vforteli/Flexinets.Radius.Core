namespace Flexinets.Radius.Core.PacketTypes
{
    public class AccountingResponse : RadiusPacket
    {
        public AccountingResponse(byte identifier) : base(PacketCode.AccountingResponse, identifier)
        {
        }

        internal AccountingResponse()
        {
        }
    }
}