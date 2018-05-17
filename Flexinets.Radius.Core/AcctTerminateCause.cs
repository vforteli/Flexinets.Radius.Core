namespace Flexinets.Radius.Core
{
    public enum AcctTerminateCause
    {
        UserRequest = 1,
        LostCarrier = 2,
        LostService = 3,
        IdleTimeout = 4,
        SessionTimeout = 5,
        AdminReset = 6,
        AdminReboot = 7,
        PortError = 8,
        NASError = 9,
        NASRequest = 10,
        NASReboot = 11,
        PortUnneeded = 12,
        PortPreempted = 13,
        PortSuspended = 14,
        ServiceUnavailable = 15,
        Callback = 16,
        UserError = 17,
        HostRequest = 18
    }
}
