namespace Flexinets.Radius.Core
{
    public enum PacketCode
    {
        AccessRequest = 1,
        AccessAccept = 2,
        AccessReject = 3,
        AccountingRequest = 4,
        AccountingResponse = 5,
        AccessChallenge = 11,
        StatusServer = 12,
        StatusClient = 13,
        DisconnectRequest = 40
    }
}
