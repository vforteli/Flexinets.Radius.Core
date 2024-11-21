namespace Flexinets.Radius.Core;

public static class TestDictionary
{
    public const string RadiusDictionary =
        """
        Attribute	1	User-Name	string
        Attribute	2	User-Password	octet
        Attribute	3	CHAP-Password	octet
        Attribute	4	NAS-IP-Address	ipaddr
        Attribute	5	NAS-Port	integer
        Attribute	6	Service-Type	integer
        Attribute	7	Framed-Protocol	integer
        Attribute	8	Framed-IP-Address	ipaddr
        Attribute	9	Framed-IP-Netmask	ipaddr
        Attribute	10	Framed-Routing	integer
        Attribute	11	Filter-Id	string
        Attribute	12	Framed-MTU	integer
        Attribute	13	Framed-Compression	integer
        Attribute	14	Login-IP-Host	ipaddr
        Attribute	15	Login-Service	integer
        Attribute	16	Login-TCP-Port	integer
        Attribute	17	Old-Password	string
        Attribute	18	Reply-Message	string
        Attribute	19	Callback-Number	string
        Attribute	20	Callback-Id	string
        Attribute	21	Expiration	date
        Attribute	22	Framed-Route	string
        Attribute	23	Framed-IPX-Network	ipaddr
        Attribute	24	State	octet
        Attribute	25	Class	string
        Attribute	26	Vendor-Specific	string
        Attribute	27	Session-Timeout	integer
        Attribute	28	Idle-Timeout	integer
        Attribute	29	Termination-Action	integer
        Attribute	30	Called-Station-Id	string
        Attribute	31	Calling-Station-Id	string
        Attribute	32	NAS-Identifier	string
        Attribute	33	Proxy-State	octet
        Attribute	34	Login-LAT-Service	string
        Attribute	35	Login-LAT-Node	string
        Attribute	36	Login-LAT-Group	string
        Attribute	37	Framed-AppleTalk-Link	integer
        Attribute	38	Framed-AppleTalk-Network	integer
        Attribute	39	Framed-AppleTalk-Zone	string
        Attribute	40	Acct-Status-Type	integer
        Attribute	41	Acct-Delay-Time	integer
        Attribute	42	Acct-Input-Octets	integer
        Attribute	43	Acct-Output-Octets	integer
        Attribute	44	Acct-Session-Id	string
        Attribute	45	Acct-Authentic	integer
        Attribute	46	Acct-Session-Time	integer
        Attribute	47	Acct-Input-Packets	integer
        Attribute	48	Acct-Output-Packets	integer
        Attribute	49	Acct-Terminate-Cause	integer
        Attribute	50	Acct-Multi-Session-Id	string
        Attribute	51	Acct-Link-Count	integer
        Attribute	52	Acct-Input-Gigawords	integer
        Attribute	53	Acct-Output-Gigawords	integer
        Attribute	55	Event-Timestamp	integer
        Attribute	60	CHAP-Challenge	octet
        Attribute	61	NAS-Port-Type	integer
        Attribute	62	Port-Limit	integer
        Attribute	63	Login-LAT-Port	string
        Attribute	64	Tunnel-Type	tagged-integer
        Attribute	65	Tunnel-Medium-Type	tagged-integer
        Attribute	66	Tunnel-Client-Endpoint	tagged-string
        Attribute	67	Tunnel-Server-Endpoint	tagged-string
        Attribute	68	Tunnel-ID	tagged-string
        Attribute	69	Tunnel-Password	string
        Attribute	70	ARAP-Password	string
        Attribute	71	ARAP-Features	string
        Attribute	72	ARAP-Zone-Access	integer
        Attribute	73	ARAP-Security	integer
        Attribute	74	ARAP-Security-Data	string
        Attribute	75	Password-Retry	integer
        Attribute	76	Prompt	integer
        Attribute	77	Connect-Info	string
        Attribute	78	Configuration-Token	octet
        Attribute	79	EAP-Message	octet
        Attribute	80	Message-Authenticator	octet
        Attribute	81	Tunnel-Private-Group-ID	tagged-string
        Attribute	82	Tunnel-Assignment-ID	tagged-string
        Attribute	83	Tunnel-Preference	tagged-integer
        Attribute	85	Acct-Interim-Interval	integer
        Attribute	86	Acct-Tunnel-Packets-Lost	integer
        Attribute	87	NAS-Port-Id	string
        Attribute	88	Framed-Pool	string
        Attribute	89	CUI	string
        Attribute	90	Tunnel-Client-Auth-ID	tagged-string
        Attribute	91	Tunnel-Server-Auth-ID	tagged-string
        Attribute	95	NAS-IPv6-Address	octet
        Attribute	96	Framed-Interface-Id	string
        Attribute	97	Framed-IPv6-Prefix	string
        Attribute	98	Login-IPv6-Host	octet
        Attribute	99	Framed-IPv6-Route	string
        Attribute	100	Gric-ARS-Server-Id	ipaddr
        Attribute	101	Error-Cause	integer
        Attribute	102	Gric-Isp-Id	string
        Attribute	103	Timestamp	integer
        Attribute	104	Gric-Timezone	integer
        Attribute	105	Gric-Request-Type	integer
        Attribute	106	Ascend-FR-Link-Status-Dlci	integer
        Attribute	107	Ascend-Calling-Subadddress	string
        Attribute	108	Ascend-Callback-Delay	integer
        Attribute	109	Ascend-Endpoint-Disc	string
        Attribute	110	Ascend-Remote-FW	string
        Attribute	111	Ascend-Multicast-GLeave-Delay	integer
        Attribute	112	Ascend-CBCP-Enable	integer
        Attribute	113	Ascend-CBCP-Mode	integer
        Attribute	114	Ascend-CBCP-Delay	integer
        Attribute	115	Ascend-CBCP-Trunk-Group	integer
        Attribute	116	Ascend-Appletalk-Route	string
        Attribute	117	Ascend-Appletalk-Peer-Mode	integer
        Attribute	118	Ascend-Route-Appletalk	integer
        Attribute	119	Ascend-FCP-Parameter	string
        Attribute	120	Ascend-Modem-PortNo	integer
        Attribute	121	Ascend-Modem-SlotNo	integer
        Attribute	122	Ascend-Modem-ShelfNo	integer
        Attribute	123	Ascend-Call-Attempt-Limit	integer
        Attribute	124	Ascend-Call-Block-Duration	integer
        Attribute	125	Ascend-Maximum-Call-Duration	integer
        Attribute	126	Ascend-Route-Preference	integer
        Attribute	127	Tunneling-Protocol	integer
        Attribute	128	Ascend-Shared-Profile-Enable	integer
        Attribute	129	Ascend-Primary-Home-Agent	string
        Attribute	130	Ascend-Secondary-Home-Agent	string
        Attribute	131	Ascend-Dialout-Allowed	integer
        Attribute	132	Ascend-Client-Gateway	ipaddr
        Attribute	133	Ascend-BACP-Enable	integer
        Attribute	134	Ascend-DHCP-Maximum-Leases	integer
        Attribute	135	Ascend-Client-Primary-DNS	ipaddr
        Attribute	136	Ascend-Client-Secondary-DNS	ipaddr
        Attribute	137	Ascend-Client-Assign-DNS	integer
        Attribute	138	Ascend-User-Acct-Type	integer
        Attribute	139	Ascend-User-Acct-Host	ipaddr
        Attribute	140	Ascend-User-Acct-Port	integer
        Attribute	141	Ascend-User-Acct-Key	string
        Attribute	142	Ascend-User-Acct-Base	integer
        Attribute	143	Ascend-User-Acct-Time	integer
        Attribute	144	Ascend-Assign-IP-Client	ipaddr
        Attribute	145	LAS-Start-Time	integer
        Attribute	146	LAS-Code	integer
        Attribute	147	LAS-Duration	integer
        Attribute	148	Local-Duration	integer
        Attribute	149	Service-Class	string
        Attribute	150	Port_Entry	string
        Attribute	155	Token-Pool	string
        Attribute	156	Ascend-FR-Circuit-Name	string
        Attribute	157	Ascend-FR-LinkUp	integer
        Attribute	158	Ascend-FR-Nailed-Grp	integer
        Attribute	159	Ascend-FR-Type	integer
        Attribute	160	Ascend-FR-Link-Mgt	integer
        Attribute	161	Ascend-FR-N391	integer
        Attribute	162	Ascend-FR-DCE-N392	integer
        Attribute	163	Ascend-FR-DTE-N392	integer
        Attribute	164	Ascend-FR-DCE-N393	integer
        Attribute	165	Ascend-FR-DTE-N393	integer
        Attribute	166	Ascend-FR-T391	integer
        Attribute	167	Ascend-FR-T392	integer
        Attribute	168	Ascend-Bridge-Address	string
        Attribute	169	Ascend-TS-Idle-Limit	integer
        Attribute	170	Ascend-TS-Idle-Mode	integer
        Attribute	171	Ascend-DBA-Monitor	integer
        Attribute	172	Ascend-Base-Channel-Count	integer
        Attribute	173	Ascend-Minimum-Channels	integer
        Attribute	174	Ascend-IPX-Route	string
        Attribute	175	Ascend-FT1-Caller	integer
        Attribute	176	Ascend-Backup	string
        Attribute	177	Ascend-Call-Type	integer
        Attribute	178	Ascend-Group	string
        Attribute	179	Ascend-FR-DLCI	integer
        Attribute	180	Ascend-FR-Profile-Name	string
        Attribute	181	Ascend-Ara-PW	string
        Attribute	182	Ascend-IPX-Node-Addr	string
        Attribute	183	Ascend-Home-Agent-IP-Addr	ipaddr
        Attribute	184	Ascend-Home-Agent-Password	string
        Attribute	185	Ascend-Home-Network-Name	string
        Attribute	186	Ascend-Home-Agent-UDP-Port	integer
        Attribute	187	Ascend-Multilink-ID	integer
        Attribute	188	Ascend-Num-In-Multilink	integer
        Attribute	189	Ascend-First-Dest	ipaddr
        Attribute	190	Ascend-Pre-Input-Octets	integer
        Attribute	191	Ascend-Pre-Output-Octets	integer
        Attribute	192	Ascend-Pre-Input-Packets	integer
        Attribute	193	Ascend-Pre-Output-Packets	integer
        Attribute	194	Ascend-Maximum-Time	integer
        Attribute	195	Ascend-Disconnect-Cause	integer
        Attribute	196	Ascend-Connect-Progress	integer
        Attribute	197	Ascend-Data-Rate	integer
        Attribute	198	Ascend-PreSession-Time	integer
        Attribute	199	Ascend-Token-Idle	integer
        Attribute	200	Ascend-Token-Immediate	integer
        Attribute	201	Ascend-Require-Auth	integer
        Attribute	202	Ascend-Number-Sessions	string
        Attribute	203	Ascend-Authen-Alias	string
        Attribute	204	Ascend-Token-Expiry	integer
        Attribute	205	Ascend-Menu-Selector	string
        Attribute	206	Ascend-Menu-Item	string
        Attribute	207	Ascend-PW-Warntime	integer
        Attribute	208	Ascend-PW-Lifetime	integer
        Attribute	209	Available-Time	integer
        Attribute	210	Info-Port	integer
        Attribute	211	Proxy-Action	string
        Attribute	212	Signature	string
        Attribute	213	Token	string
        Attribute	214	Acct-Rate	string
        Attribute	215	Acct-Charge	string
        Attribute	216	Acct-Transaction-Id	string
        Attribute	217	Acct-Charge-Allowed	string
        Attribute	218	Maximum-Time	integer
        Attribute	219	Ascend-FR-Direct	integer
        Attribute	220	Time-Used	integer
        Attribute	221	Huntgroup-Name	string
        Attribute	222	User-Id	string
        Attribute	223	User-Realm	string
        Attribute	224	Ascend-IPX-Alias	integer
        Attribute	225	Ascend-Metric	integer
        Attribute	226	Ascend-PRI-Number-Type	integer
        Attribute	227	Ascend-Dial-Number	string
        Attribute	228	Ascend-Route-IP	integer
        Attribute	229	Ascend-Route-IPX	integer
        Attribute	230	Ascend-Bridge	integer
        Attribute	231	Ascend-Send-Auth	integer
        Attribute	232	Ascend-Send-Passwd	string
        Attribute	233	Ascend-Link-Compression	integer
        Attribute	234	Ascend-Target-Util	integer
        Attribute	235	Ascend-Maximum-Channels	integer
        Attribute	236	Ascend-Inc-Channel-Count	integer
        Attribute	237	Ascend-Dec-Channel-Count	integer
        Attribute	238	Ascend-Seconds-Of-History	integer
        Attribute	239	Ascend-History-Weigh-Type	integer
        Attribute	240	Ascend-Add-Seconds	integer
        Attribute	241	Ascend-Remove-Seconds	integer
        Attribute	242	Ascend-Data-Filter	abinary
        Attribute	243	Ascend-Call-Filter	abinary
        Attribute	244	Ascend-Idle-Limit	integer
        Attribute	245	Ascend-Preempt-Limit	integer
        Attribute	246	Ascend-Callback	integer
        Attribute	247	Ascend-Data-Svc	integer
        Attribute	248	Ascend-Force-56	integer
        Attribute	249	Ascend-Billing-Number	string
        Attribute	250	Ascend-Call-By-Call	integer
        Attribute	251	Ascend-Transit-Number	string
        Attribute	252	Ascend-Host-Info	string
        Attribute	253	Ascend-PPP-Address	ipaddr
        Attribute	254	Ascend-MPP-Idle-Percent	integer
        Attribute	255	Ascend-Xmit-Rate	integer


        # VendorId 5
        VendorSpecificAttribute	5	1	Acc-Reason-Code	integer
        VendorSpecificAttribute	5	2	Acc-Ccp-Option	integer
        VendorSpecificAttribute	5	3	Acc-Input-Errors	integer
        VendorSpecificAttribute	5	4	Acc-Output-Errors	integer
        VendorSpecificAttribute	5	5	Acc-Access-Partition	string
        VendorSpecificAttribute	5	6	Acc-Customer-Id	string
        VendorSpecificAttribute	5	7	Acc-Ip-Gateway-Pri	ipaddr
        VendorSpecificAttribute	5	8	Acc-Ip-Gateway-Sec	ipaddr
        VendorSpecificAttribute	5	9	Acc-Route-Policy	integer
        VendorSpecificAttribute	5	10	Acc-ML-MLX-Admin-State	integer
        VendorSpecificAttribute	5	11	Acc-ML-Call-Threshold	integer
        VendorSpecificAttribute	5	12	Acc-ML-Clear-Threshold	integer
        VendorSpecificAttribute	5	13	Acc-ML-Damping-Factor	integer
        VendorSpecificAttribute	5	14	Acc-Tunnel-Secret	string
        VendorSpecificAttribute	5	15	Acc-Clearing-Cause	integer
        VendorSpecificAttribute	5	16	Acc-Clearing-Location	integer
        VendorSpecificAttribute	5	17	Acc-Service-Profile	string
        VendorSpecificAttribute	5	18	Acc-Request-Type	integer
        VendorSpecificAttribute	5	19	Acc-Bridging-Support	integer
        VendorSpecificAttribute	5	20	Acc-Vpsm-Oversubscribed	integer
        VendorSpecificAttribute	5	21	Acc-Acct-On-Off-Reason	integer
        VendorSpecificAttribute	5	22	Acc-Tunnel-Port	integer
        VendorSpecificAttribute	5	23	Acc-Dns-Server-Pri	ipaddr
        VendorSpecificAttribute	5	24	Acc-Dns-Server-Sec	ipaddr
        VendorSpecificAttribute	5	25	Acc-Nbns-Server-Pri	ipaddr
        VendorSpecificAttribute	5	26	Acc-Nbns-Server-Sec	ipaddr
        VendorSpecificAttribute	5	27	Acc-Dial-Port-Index	integer
        VendorSpecificAttribute	5	28	Acc-Ip-Compression	integer
        VendorSpecificAttribute	5	29	Acc-Ipx-Compression	integer
        VendorSpecificAttribute	5	30	Acc-Connect-Tx-Speed	integer
        VendorSpecificAttribute	5	31	Acc-Connect-Rx-Speed	integer
        VendorSpecificAttribute	5	32	Acc-Modem_Modulation_Type	string
        VendorSpecificAttribute	5	33	Acc-Modem_Error_Protocol	string
        VendorSpecificAttribute	5	34	Acc-Callback-Delay	integer
        VendorSpecificAttribute	5	35	Acc-Callback-Num-Valid	string
        VendorSpecificAttribute	5	36	Acc-Callback-Mode	integer
        VendorSpecificAttribute	5	37	Acc-Callback-CBCP-Type	integer
        VendorSpecificAttribute	5	38	Acc-Dialout-Auth-Mode	integer
        VendorSpecificAttribute	5	39	Acc-Dialout-Auth-Password	string
        VendorSpecificAttribute	5	40	Acc-Dialout-Auth-UserName	string
        VendorSpecificAttribute	5	42	Acc-Access-Community	integer
        VendorSpecificAttribute	5	80	Ipass-5-80	string
        VendorSpecificAttribute	5	81	Ipass-5-81	string
        VendorSpecificAttribute	5	82	Ipass-5-82	string
        VendorSpecificAttribute	5	83	Ipass-5-83	string
        VendorSpecificAttribute	5	84	Ipass-5-84	string
        VendorSpecificAttribute	5	99	Ipass-5-99	string

        # VendorId 9
        VendorSpecificAttribute	9	1	cisco-avpair	string
        VendorSpecificAttribute	9	2	Cisco-NAS-Port	string
        VendorSpecificAttribute	9	23	cisco-h323-remote-address	string
        VendorSpecificAttribute	9	24	cisco-h323-conf-id	string
        VendorSpecificAttribute	9	25	cisco-h323-setup-time	string
        VendorSpecificAttribute	9	26	cisco-h323-call-origin	string
        VendorSpecificAttribute	9	27	cisco-h323-call-type	string
        VendorSpecificAttribute	9	28	cisco-h323-connect-time	string
        VendorSpecificAttribute	9	29	cisco-h323-disconnect-time	string
        VendorSpecificAttribute	9	30	cisco-h323-disconnect-cause	string
        VendorSpecificAttribute	9	31	cisco-h323-voice-quality	string
        VendorSpecificAttribute	9	32	cisco-h323-ivr-out	string
        VendorSpecificAttribute	9	33	cisco-h323-gw-id	string
        VendorSpecificAttribute	9	34	cisco-h323-call-treatment	string
        VendorSpecificAttribute	9	37	cisco-Policy-Up	string
        VendorSpecificAttribute	9	38	cisco-Policy-Down	string
        VendorSpecificAttribute	9	66	cisco-VPNPassword	string
        VendorSpecificAttribute	9	67	cisco-VPNGroupInfo	string
        VendorSpecificAttribute	9	100	cisco-h323-ivr-in	string
        VendorSpecificAttribute	9	101	cisco-h323-credit-amount	string
        VendorSpecificAttribute	9	102	cisco-h323-credit-time	string
        VendorSpecificAttribute	9	103	cisco-h323-return-code	string
        VendorSpecificAttribute	9	104	cisco-h323-prompt-id	string
        VendorSpecificAttribute	9	105	cisco-h323-time-and-day	string
        VendorSpecificAttribute	9	106	cisco-h323-redirect-number	string
        VendorSpecificAttribute	9	107	cisco-h323-preferred-lang	string
        VendorSpecificAttribute	9	108	cisco-h323-redirect-ip-addr	string
        VendorSpecificAttribute	9	109	cisco-h323-billing-model	string
        VendorSpecificAttribute	9	110	cisco-h323-currency-type	string
        VendorSpecificAttribute	9	187	Cisco-Multilink-ID	integer
        VendorSpecificAttribute	9	188	Cisco-Num-In-Multilink	integer
        VendorSpecificAttribute	9	190	Cisco-Pre-Input-Octets	integer
        VendorSpecificAttribute	9	191	Cisco-Pre-Output-Octets	integer
        VendorSpecificAttribute	9	192	Cisco-Pre-Input-Packets	integer
        VendorSpecificAttribute	9	193	Cisco-Pre-Output-Packets	integer
        VendorSpecificAttribute	9	194	Cisco-Maximun-Time	integer
        VendorSpecificAttribute	9	195	Cisco-Disconnect-Cause	integer
        VendorSpecificAttribute	9	197	Cisco-Data-Rate	integer
        VendorSpecificAttribute	9	198	Cisco-PreSession-Time	integer
        VendorSpecificAttribute	9	208	Cisco-PW-Lifetime	integer
        VendorSpecificAttribute	9	209	Cisco-IP-Direct	integer
        VendorSpecificAttribute	9	210	Cisco-PPP-VJ-Slot-Comp	integer
        VendorSpecificAttribute	9	212	Cisco-PPP-Async-Map	integer
        VendorSpecificAttribute	9	217	Cisco-IP-Pool-Definition	integer
        VendorSpecificAttribute	9	218	Cisco-Asing-IP-Pool	integer
        VendorSpecificAttribute	9	228	Cisco-Route-IP	integer
        VendorSpecificAttribute	9	233	Cisco-Link-Compression	integer
        VendorSpecificAttribute	9	234	Cisco-Target-Util	integer
        VendorSpecificAttribute	9	235	Cisco-Maximun-Channels	integer
        VendorSpecificAttribute	9	242	Cisco-Data-Filter	integer
        VendorSpecificAttribute	9	243	Cisco-Call-Filter	integer
        VendorSpecificAttribute	9	244	Cisco-Idle-Limit	integer
        VendorSpecificAttribute	9	250	Account-Info	string
        VendorSpecificAttribute	9	251	Service-Info	string
        VendorSpecificAttribute	9	252	Command-Code	string
        VendorSpecificAttribute	9	253	Control-Info	string
        VendorSpecificAttribute	9	255	Cisco-Xmit-Rate	integer

        # VendorId 43
        VendorSpecificAttribute	43	1	3COM-User-Access-Level	integer

        # VendorId 61
        VendorSpecificAttribute	61	211	Proxy-Action	string
        VendorSpecificAttribute	61	222	User-Id	string
        VendorSpecificAttribute	61	223	User-Realm	string

        # VendorId 166
        VendorSpecificAttribute	166	1	Shiva-User-Attributes	string
        VendorSpecificAttribute	166	2	Shiva-Service-Type	integer
        VendorSpecificAttribute	166	3	Shiva-VPN-Group	string
        VendorSpecificAttribute	166	4	Shiva-External-Ip-Addr	ipaddr
        VendorSpecificAttribute	166	5	Shiva-Internal-Ip-Addr	ipaddr
        VendorSpecificAttribute	166	30	Shiva-Compression	integer
        VendorSpecificAttribute	166	31	Shiva-Dialback-Delay	integer
        VendorSpecificAttribute	166	32	Shiva-Call-Durn-Trap	integer
        VendorSpecificAttribute	166	33	Shiva-Bandwidth-Trap	integer
        VendorSpecificAttribute	166	34	Shiva-Minimum-Call	integer
        VendorSpecificAttribute	166	35	Shiva-Default-Host	string
        VendorSpecificAttribute	166	36	Shiva-Menu-Name	string
        VendorSpecificAttribute	166	37	Shiva-User-Flags	string
        VendorSpecificAttribute	166	38	Shiva-Termtype	string
        VendorSpecificAttribute	166	39	Shiva-Break-Key	string
        VendorSpecificAttribute	166	40	Shiva-Fwd-Key	string
        VendorSpecificAttribute	166	41	Shiva-Bak-Key	string
        VendorSpecificAttribute	166	42	Shiva-Dial-Timeout	integer
        VendorSpecificAttribute	166	43	Shiva-LAT-Port	string
        VendorSpecificAttribute	166	44	Shiva-Max-VCs	integer
        VendorSpecificAttribute	166	45	Shiva-DHCP-Leasetime	integer
        VendorSpecificAttribute	166	46	Shiva-LAT-Groups	string
        VendorSpecificAttribute	166	60	Shiva-RTC-Timestamp	integer
        VendorSpecificAttribute	166	61	Shiva-Circuit-Type	integer
        VendorSpecificAttribute	166	90	Shiva-Called-Number	string
        VendorSpecificAttribute	166	91	Shiva-Calling-Number	string
        VendorSpecificAttribute	166	92	Shiva-Customer-ID	string
        VendorSpecificAttribute	166	93	Shiva-Type-of-Service	integer
        VendorSpecificAttribute	166	94	Shiva-Link-Speed	integer
        VendorSpecificAttribute	166	95	Shiva-Links-In-Bundle	integer
        VendorSpecificAttribute	166	96	Shiva-Compression-Type	integer
        VendorSpecificAttribute	166	97	Shiva-Link-Protocol	integer
        VendorSpecificAttribute	166	98	Shiva-Network-Protocols	integer
        VendorSpecificAttribute	166	99	Shiva-Session-Id	integer
        VendorSpecificAttribute	166	100	Shiva-Disconnect-Reason	integer
        VendorSpecificAttribute	166	101	Shiva-Acct-Serv-Switch	ipaddr
        VendorSpecificAttribute	166	102	Shiva-Event-Flags	integer
        VendorSpecificAttribute	166	103	Shiva-Function	integer
        VendorSpecificAttribute	166	104	Shiva-Connect-Reason	integer

        # VendorId 307
        VendorSpecificAttribute	307	2	LE-Terminate-Detail	string
        VendorSpecificAttribute	307	3	LE-Advice-of-Charge	string
        VendorSpecificAttribute	307	4	LE-Connect-Detail	string
        VendorSpecificAttribute	307	6	LE-IP-Pool	string
        VendorSpecificAttribute	307	7	LE-IP-Gateway	ipaddr
        VendorSpecificAttribute	307	8	LE-Modem-Info	string
        VendorSpecificAttribute	307	9	LE-IPSec-Log-Options	integer
        VendorSpecificAttribute	307	10	LE-IPSec-Deny-Action	integer
        VendorSpecificAttribute	307	11	LE-IPSec-Active-Profile	string
        VendorSpecificAttribute	307	12	LE-IPSec-Outsource-Profile	string
        VendorSpecificAttribute	307	13	LE-IPSec-Passive-Profile	string
        VendorSpecificAttribute	307	14	LE-NAT-TCP-Session-Timeout	integer
        VendorSpecificAttribute	307	15	LE-NAT-Other-Session-Timeout	integer
        VendorSpecificAttribute	307	16	LE-NAT-Log-Options	integer
        VendorSpecificAttribute	307	17	LE-NAT-Sess-Dir-Fail-Action	integer
        VendorSpecificAttribute	307	18	LE-NAT-Inmap	string
        VendorSpecificAttribute	307	19	LE-NAT-Outmap	string
        VendorSpecificAttribute	307	20	LE-NAT-Outsource-Inmap	string
        VendorSpecificAttribute	307	21	LE-NAT-Outsource-Outmap	string
        VendorSpecificAttribute	307	22	LE-Admin-Group	string
        VendorSpecificAttribute	307	23	LE-Multicast-Client	integer

        # VendorId 311
        VendorSpecificAttribute	311	1	MS-CHAP-Response	octet
        VendorSpecificAttribute	311	2	MS-CHAP-Error	string
        VendorSpecificAttribute	311	3	MS-CHAP-CPW-1	string
        VendorSpecificAttribute	311	4	MS-CHAP-CPW-2	string
        VendorSpecificAttribute	311	5	MS-CHAP-LM-Enc-PW	string
        VendorSpecificAttribute	311	6	MS-CHAP-NT-Enc-PW	string
        VendorSpecificAttribute	311	7	MS-MPPE-Encryption-Policy	integer
        VendorSpecificAttribute	311	8	MS-MPPE-Encryption-Types	integer
        VendorSpecificAttribute	311	9	MS-RAS-Vendor	integer
        VendorSpecificAttribute	311	10	MS-CHAP-Domain	string
        VendorSpecificAttribute	311	11	MS-CHAP-Challenge	octet
        VendorSpecificAttribute	311	12	MS-CHAP-MPPE-Keys	string
        VendorSpecificAttribute	311	13	MS-BAP-Usage	integer
        VendorSpecificAttribute	311	14	MS-Link-Utilization-Threshold	integer
        VendorSpecificAttribute	311	15	MS-Link-Drop-Time-Limit	integer
        VendorSpecificAttribute	311	16	MS-MPPE-Send-Key	octet
        VendorSpecificAttribute	311	17	MS-MPPE-Recv-Key	octet
        VendorSpecificAttribute	311	18	MS-RAS-Version	string
        VendorSpecificAttribute	311	19	MS-Old-ARAP-Password	string
        VendorSpecificAttribute	311	20	MS-New-ARAP-Password	string
        VendorSpecificAttribute	311	21	MS-ARAP-Password-Change-Reason	string
        VendorSpecificAttribute	311	22	MS-Filter	string
        VendorSpecificAttribute	311	23	MS-Acct-Auth-Type	integer
        VendorSpecificAttribute	311	24	MS-Acct-EAP-Type	integer
        VendorSpecificAttribute	311	25	MS-CHAP2-Response	octet
        VendorSpecificAttribute	311	26	MS-CHAP2-Success	string
        VendorSpecificAttribute	311	27	MS-CHAP2-CPW	string
        VendorSpecificAttribute	311	28	MS-Primary-DNS-Server	ipaddr
        VendorSpecificAttribute	311	29	MS-Secondary-DNS-Server	ipaddr
        VendorSpecificAttribute	311	30	MS-Primary-NBNS-Server	ipaddr
        VendorSpecificAttribute	311	31	MS-Secondary-NBNS-Server	ipaddr
        VendorSpecificAttribute	311	33	MS-ARAP-Challenge	string

        # VendorId 318
        VendorSpecificAttribute	318	1	APC-Service-Type	integer
        VendorSpecificAttribute	318	2	APC-Outlets	string

        # VendorId 429
        VendorSpecificAttribute	429	72	USR-DTE-Data-Idle-Timeout	integer
        VendorSpecificAttribute	429	94	USR-Default-DTE-Data-Rate	integer
        VendorSpecificAttribute	429	102	USR-Last-Number-Dialed-Out	string
        VendorSpecificAttribute	429	103	USR-Sync-Async-Mode	integer
        VendorSpecificAttribute	429	104	USR-Originate-Answer-Mode	integer
        VendorSpecificAttribute	429	105	USR-Failure-to-Connect-Reason	integer
        VendorSpecificAttribute	429	106	USR-Initial-Tx-Link-Data-Rate	integer
        VendorSpecificAttribute	429	107	USR-Final-Tx-Link-Data-Rate	integer
        VendorSpecificAttribute	429	108	USR-Modulation-Type	integer
        VendorSpecificAttribute	429	111	USR-Equalization-Type	integer
        VendorSpecificAttribute	429	112	USR-Fallback-Enabled	integer
        VendorSpecificAttribute	429	113	USR-Characters-Sent	integer
        VendorSpecificAttribute	429	114	USR-Characters-Received	integer
        VendorSpecificAttribute	429	117	USR-Blocks-Sent	integer
        VendorSpecificAttribute	429	118	USR-Blocks-Received	integer
        VendorSpecificAttribute	429	119	USR-Blocks-Resent	integer
        VendorSpecificAttribute	429	120	USR-Retrains-Requested	integer
        VendorSpecificAttribute	429	121	USR-Retrains-Granted	integer
        VendorSpecificAttribute	429	122	USR-Line-Reversals	integer
        VendorSpecificAttribute	429	123	USR-Number-of-Characters-Lost	integer
        VendorSpecificAttribute	429	124	USR-Back-Channel-Data-Rate	integer
        VendorSpecificAttribute	429	125	USR-Number-of-Blers	integer
        VendorSpecificAttribute	429	126	USR-Number-of-Link-Timeouts	integer
        VendorSpecificAttribute	429	127	USR-Number-of-Fallbacks	integer
        VendorSpecificAttribute	429	128	USR-Number-of-Upshifts	integer
        VendorSpecificAttribute	429	129	USR-Number-of-Link-NAKs	integer
        VendorSpecificAttribute	429	153	USR-Simplified-MNP-Levels	integer
        VendorSpecificAttribute	429	155	USR-Connect-Term-Reason	integer
        VendorSpecificAttribute	429	190	USR-DTR-False-Timeout	integer
        VendorSpecificAttribute	429	191	USR-Fallback-Limit	integer
        VendorSpecificAttribute	429	192	USR-Block-Error-Count-Limit	integer
        VendorSpecificAttribute	429	199	USR-Simplified-V42bis-Usage	integer
        VendorSpecificAttribute	429	218	USR-DTR-True-Timeout	integer
        VendorSpecificAttribute	429	232	USR-Last-Number-Dialed-In-DNIS	string
        VendorSpecificAttribute	429	233	USR-Last-Callers-Number-ANI	string
        VendorSpecificAttribute	429	388	USR-Mbi_Ct_PRI_Card_Slot	integer
        VendorSpecificAttribute	429	389	USR-Mbi_Ct_TDM_Time_Slot	integer
        VendorSpecificAttribute	429	390	USR-Mbi_Ct_PRI_Card_Span_Line	integer
        VendorSpecificAttribute	429	391	USR-Mbi_Ct_BChannel_Used	integer
        VendorSpecificAttribute	429	36864	USR-IP-Input-Filter	string
        VendorSpecificAttribute	429	36865	USR-IPX-Input-Filter	string
        VendorSpecificAttribute	429	36866	USR-SAP-Input-Filter	string
        VendorSpecificAttribute	429	36867	USR-IP-Output-Filter	string
        VendorSpecificAttribute	429	36868	USR-IPX-Output-Filter	string
        VendorSpecificAttribute	429	36869	USR-SAP-Output-Filter	string
        VendorSpecificAttribute	429	36870	USR-VPN-ID	integer
        VendorSpecificAttribute	429	36871	USR-VPN-Name	string
        VendorSpecificAttribute	429	36872	USR-VPN-Neighbor	ipaddr
        VendorSpecificAttribute	429	36873	USR-Framed-Routing-V2	integer
        VendorSpecificAttribute	429	36874	USR-VPN-Gateway	string
        VendorSpecificAttribute	429	36875	USR-Tunnel-Authenticator	string
        VendorSpecificAttribute	429	36876	USR-Packet-Index	string
        VendorSpecificAttribute	429	36877	USR-Packet-Cutoff	string
        VendorSpecificAttribute	429	36878	USR-Access-Accept-Packet	string
        VendorSpecificAttribute	429	36879	USR-Primary-DNS-Server	ipaddr
        VendorSpecificAttribute	429	36880	USR-Secondary-DNS-Server	ipaddr
        VendorSpecificAttribute	429	36881	USR-Primary-NBNS-Server	ipaddr
        VendorSpecificAttribute	429	36882	USR-Secondary-NBNS-Server	ipaddr
        VendorSpecificAttribute	429	36883	USR-Syslog-Tap	integer
        VendorSpecificAttribute	429	36884	USR-Message-Integrity-Check	string
        VendorSpecificAttribute	429	36887	USR-Log-Filter-Packet	integer
        VendorSpecificAttribute	429	36889	USR-Chassis-Call-Slot	integer
        VendorSpecificAttribute	429	36890	USR-Chassis-Call-Span	integer
        VendorSpecificAttribute	429	36891	USR-Chassis-Call-Channel	integer
        VendorSpecificAttribute	429	36892	USR-Keypress-Timeout	integer
        VendorSpecificAttribute	429	36893	USR-Unauthenticated-Time	integer
        VendorSpecificAttribute	429	36894	USR-VPN-Encrypter	string
        VendorSpecificAttribute	429	36895	USR-Acct-VPN-Gateway	string
        VendorSpecificAttribute	429	36896	USR-Re-CHAP-Timeout	integer
        VendorSpecificAttribute	429	36899	USR-Connect-Speed	integer
        VendorSpecificAttribute	429	36900	USR-Framed-IP-Address-Pool-Name	string
        VendorSpecificAttribute	429	36901	USR-MP-EDO	string
        VendorSpecificAttribute	429	38912	USR-Bearer-Capabilities	integer
        VendorSpecificAttribute	429	38913	USR-Speed-of-Connection	integer
        VendorSpecificAttribute	429	38914	USR-Max-Channels	integer
        VendorSpecificAttribute	429	38915	USR-Channel-Expansion	integer
        VendorSpecificAttribute	429	38916	USR-Channel-Decrement	integer
        VendorSpecificAttribute	429	38917	USR-Expansion-Algorithm	integer
        VendorSpecificAttribute	429	38918	USR-Compression-Algorithm	integer
        VendorSpecificAttribute	429	38919	USR-Receive-Acc-Map	integer
        VendorSpecificAttribute	429	38920	USR-Transmit-Acc-Map	integer
        VendorSpecificAttribute	429	38922	USR-Compression-Reset-Mode	integer
        VendorSpecificAttribute	429	38923	USR-Min-Compression-Size	integer
        VendorSpecificAttribute	429	38924	USR-IP	integer
        VendorSpecificAttribute	429	38925	USR-IPX	integer
        VendorSpecificAttribute	429	38926	USR-Filter-Zones	integer
        VendorSpecificAttribute	429	38927	USR-Appletalk	integer
        VendorSpecificAttribute	429	38928	USR-Bridging	integer
        VendorSpecificAttribute	429	38929	USR-Spoofing	integer
        VendorSpecificAttribute	429	38930	USR-Host-Type	integer
        VendorSpecificAttribute	429	38931	USR-Send-Name	string
        VendorSpecificAttribute	429	38932	USR-Send-Password	string
        VendorSpecificAttribute	429	38933	USR-Start-Time	integer
        VendorSpecificAttribute	429	38934	USR-End-Time	integer
        VendorSpecificAttribute	429	38935	USR-Send-Script1	string
        VendorSpecificAttribute	429	38936	USR-Reply-Script1	string
        VendorSpecificAttribute	429	38937	USR-Send-Script2	string
        VendorSpecificAttribute	429	38938	USR-Reply-Script2	string
        VendorSpecificAttribute	429	38939	USR-Send-Script3	string
        VendorSpecificAttribute	429	38940	USR-Reply-Script3	string
        VendorSpecificAttribute	429	38941	USR-Send-Script4	string
        VendorSpecificAttribute	429	38942	USR-Reply-Script4	string
        VendorSpecificAttribute	429	38943	USR-Send-Script5	string
        VendorSpecificAttribute	429	38944	USR-Reply-Script5	string
        VendorSpecificAttribute	429	38945	USR-Send-Script6	string
        VendorSpecificAttribute	429	38946	USR-Reply-Script6	string
        VendorSpecificAttribute	429	38947	USR-Terminal-Type	string
        VendorSpecificAttribute	429	38948	USR-Appletalk-Network-Range	integer
        VendorSpecificAttribute	429	38949	USR-Local-IP-Address	string
        VendorSpecificAttribute	429	38950	USR-Routing-Protocol	integer
        VendorSpecificAttribute	429	38951	USR-Modem-Group	integer
        VendorSpecificAttribute	429	38959	USR-MP-MRRU	integer
        VendorSpecificAttribute	429	38977	USR-MP-EDO	string
        VendorSpecificAttribute	429	38978	USR-Modem-Training-Time	integer
        VendorSpecificAttribute	429	38979	USR-Interface-Index	integer
        VendorSpecificAttribute	429	38998	USR-VTS-Session-Key	string
        VendorSpecificAttribute	429	39000	USR-Call-Arrived-Time	integer
        VendorSpecificAttribute	429	39001	USR-Call-Lost-Time	integer
        VendorSpecificAttribute	429	39016	USR-Tunnel-Switch-Endpoint	string
        VendorSpecificAttribute	429	39020	USR-Acct-Reason	string
        VendorSpecificAttribute	429	39049	USR-Tunnel-Supports-Tags	integer
        VendorSpecificAttribute	429	39051	USR-Disconnect-Reason	integer
        VendorSpecificAttribute	429	39079	USR-Bogus-39079	string
        VendorSpecificAttribute	429	39080	USR-Bogus-39080	string
        VendorSpecificAttribute	429	39087	USR-Bogus-39087	string
        VendorSpecificAttribute	429	39090	USR-Bogus-39090	string
        VendorSpecificAttribute	429	39091	USR-Bogus-39091	string
        VendorSpecificAttribute	429	39092	USR-Bogus-39092	string
        VendorSpecificAttribute	429	48733	USR-Channel-Connected-To	integer
        VendorSpecificAttribute	429	48734	USR-Slot-Connected-To	integer
        VendorSpecificAttribute	429	48735	USR-Device-Connected-To	integer
        VendorSpecificAttribute	429	48736	USR-NFAS-ID	integer
        VendorSpecificAttribute	429	48737	USR-Q931-Call-Reference-Value	integer
        VendorSpecificAttribute	429	48738	USR-Call-Event-Code	integer
        VendorSpecificAttribute	429	48739	USR-DS0	integer
        VendorSpecificAttribute	429	48740	USR-DS0s	string
        VendorSpecificAttribute	429	48742	USR-Gateway-IP-Address	ipaddr
        VendorSpecificAttribute	429	48759	USR-Physical-State	integer
        VendorSpecificAttribute	429	48772	USR-Chassis-Temp-Threshold	integer
        VendorSpecificAttribute	429	48773	USR-Card-Type	integer
        VendorSpecificAttribute	429	48862	USR-Security-Login-Limit	integer
        VendorSpecificAttribute	429	48890	USR-Security-Resp-Limit	integer
        VendorSpecificAttribute	429	48916	USR-Packet-Bus-Session	integer
        VendorSpecificAttribute	429	48919	USR-DTE-Ring-No-Answer-Limit	integer
        VendorSpecificAttribute	429	48940	USR-Final-Rx-Link-Data-Rate	integer
        VendorSpecificAttribute	429	48941	USR-Initial-Rx-Link-Data-Rate	integer
        VendorSpecificAttribute	429	48943	USR-Event-Date-Time	integer
        VendorSpecificAttribute	429	48945	USR-Chassis-Temperature	integer
        VendorSpecificAttribute	429	48946	USR-Actual-Voltage	integer
        VendorSpecificAttribute	429	48947	USR-Expected-Voltage	integer
        VendorSpecificAttribute	429	48948	USR-Power-Supply-Number	integer
        VendorSpecificAttribute	429	48952	USR-Channel	integer
        VendorSpecificAttribute	429	48953	USR-Chassis-Slot	integer
        VendorSpecificAttribute	429	49086	USR-Event-Id	integer
        VendorSpecificAttribute	429	49126	USR-Number-of-Rings-Limit	integer
        VendorSpecificAttribute	429	49127	USR-Connect-Time-Limit	integer
        VendorSpecificAttribute	429	49142	USR-Call-End-Date-Time	integer
        VendorSpecificAttribute	429	49143	USR-Call-Start-Date-Time	integer
        VendorSpecificAttribute	429	61440	USR-Server-Time	integer

        # VendorId 529
        VendorSpecificAttribute	529	2	Ascend-Max-Shared-Users	integer
        VendorSpecificAttribute	529	3	Ascend-IP-DSCP	integer
        VendorSpecificAttribute	529	4	Ascend-X25-X121-Source-Address	string
        VendorSpecificAttribute	529	5	Ascend-PPP-Circuit	integer
        VendorSpecificAttribute	529	6	Ascend-PPP-Circuit-Name	string
        VendorSpecificAttribute	529	7	Ascend-UU-Info	string
        VendorSpecificAttribute	529	8	Ascend-User-Priority	integer
        VendorSpecificAttribute	529	9	Ascend-CIR-Timer	integer
        VendorSpecificAttribute	529	10	Ascend-FR-08-Mode	integer
        VendorSpecificAttribute	529	11	Ascend-Destination-Nas-Port	integer
        VendorSpecificAttribute	529	12	Ascend-FR-SVC-Addr	string
        VendorSpecificAttribute	529	13	Ascend-NAS-Port-Format	integer
        VendorSpecificAttribute	529	14	Ascend-ATM-Fault-Management	integer
        VendorSpecificAttribute	529	15	Ascend-ATM-Loopback-Cell-Loss	integer
        VendorSpecificAttribute	529	16	Ascend-Ckt-Type	integer
        VendorSpecificAttribute	529	17	Ascend-SVC-Enabled	integer
        VendorSpecificAttribute	529	18	Ascend-Session-Type	integer
        VendorSpecificAttribute	529	19	Ascend-H323-Gatekeeper	ipaddr
        VendorSpecificAttribute	529	20	Ascend-Global-Call-Id	string
        VendorSpecificAttribute	529	21	Ascend-H323-Conference-Id	integer
        VendorSpecificAttribute	529	22	Ascend-H323-Fegw-Address	ipaddr
        VendorSpecificAttribute	529	23	Ascend-H323-Dialed-Time	integer
        VendorSpecificAttribute	529	24	Ascend-Dialed-Number	string
        VendorSpecificAttribute	529	25	Ascend-Inter-Arrival-Jitter	integer
        VendorSpecificAttribute	529	26	Ascend-Dropped-Octets	integer
        VendorSpecificAttribute	529	27	Ascend-Dropped-Packets	integer
        VendorSpecificAttribute	529	28	Ascend-Auth-Delay	integer
        VendorSpecificAttribute	529	29	Ascend-X25-Pad-X3-Profile	integer
        VendorSpecificAttribute	529	30	Ascend-X25-Pad-X3-Parameters	string
        VendorSpecificAttribute	529	31	Ascend-Tunnel-VRouter-Name	string
        VendorSpecificAttribute	529	32	Ascend-X25-Reverse-Charging	integer
        VendorSpecificAttribute	529	33	Ascend-X25-Nui-Prompt	string
        VendorSpecificAttribute	529	34	Ascend-X25-Nui-Password-Prompt	string
        VendorSpecificAttribute	529	35	Ascend-X25-Cug	string
        VendorSpecificAttribute	529	36	Ascend-X25-Pad-Alias-1	string
        VendorSpecificAttribute	529	37	Ascend-X25-Pad-Alias-2	string
        VendorSpecificAttribute	529	38	Ascend-X25-Pad-Alias-3	string
        VendorSpecificAttribute	529	39	Ascend-X25-X121-Address	string
        VendorSpecificAttribute	529	40	Ascend-X25-Nui	string
        VendorSpecificAttribute	529	41	Ascend-X25-Rpoa	string
        VendorSpecificAttribute	529	42	Ascend-X25-Pad-Prompt	string
        VendorSpecificAttribute	529	43	Ascend-X25-Pad-Banner	string
        VendorSpecificAttribute	529	44	Ascend-X25-Profile-Name	string
        VendorSpecificAttribute	529	45	Ascend-Recv-Name	string
        VendorSpecificAttribute	529	46	Ascend-Bi-Directional-Auth	integer
        VendorSpecificAttribute	529	47	Ascend-MTU	integer
        VendorSpecificAttribute	529	48	Ascend-Call-Direction	integer
        VendorSpecificAttribute	529	49	Ascend-Service-Type	integer
        VendorSpecificAttribute	529	50	Ascend-Filter-Required	integer
        VendorSpecificAttribute	529	51	Ascend-Traffic-Shaper	integer
        VendorSpecificAttribute	529	52	Ascend-Access-Intercept-LEA	string
        VendorSpecificAttribute	529	53	Ascend-Access-Intercept-Log	string
        VendorSpecificAttribute	529	54	Ascend-Private-Route-Table-ID	string
        VendorSpecificAttribute	529	55	Ascend-Private-Route-Required	integer
        VendorSpecificAttribute	529	56	Ascend-Cache-Refresh	integer
        VendorSpecificAttribute	529	57	Ascend-Cache-Time	integer
        VendorSpecificAttribute	529	58	Ascend-Egress-Enabled	integer
        VendorSpecificAttribute	529	59	Ascend-QOS-Upstream	string
        VendorSpecificAttribute	529	60	Ascend-QOS-Downstream	string
        VendorSpecificAttribute	529	61	Ascend-ATM-Connect-Vpi	integer
        VendorSpecificAttribute	529	62	Ascend-ATM-Connect-Vci	integer
        VendorSpecificAttribute	529	63	Ascend-ATM-Connect-Group	integer
        VendorSpecificAttribute	529	64	Ascend-ATM-Group	integer
        VendorSpecificAttribute	529	65	Ascend-IPX-Header-Compression	integer
        VendorSpecificAttribute	529	66	Ascend-Calling-Id-Type-Of-Num	integer
        VendorSpecificAttribute	529	67	Ascend-Calling-Id-Number-Plan	integer
        VendorSpecificAttribute	529	68	Ascend-Calling-Id-Presentatn	integer
        VendorSpecificAttribute	529	69	Ascend-Calling-Id-Screening	integer
        VendorSpecificAttribute	529	70	Ascend-BIR-Enable	integer
        VendorSpecificAttribute	529	71	Ascend-BIR-Proxy	integer
        VendorSpecificAttribute	529	72	Ascend-BIR-Bridge-Group	integer
        VendorSpecificAttribute	529	73	Ascend-IPSEC-Profile	string
        VendorSpecificAttribute	529	74	Ascend-PPPoE-Enable	integer
        VendorSpecificAttribute	529	75	Ascend-Bridge-Non-PPPoE	integer
        VendorSpecificAttribute	529	76	Ascend-ATM-Direct	integer
        VendorSpecificAttribute	529	77	Ascend-ATM-Direct-Profile	string
        VendorSpecificAttribute	529	78	Ascend-Client-Primary-WINS	ipaddr
        VendorSpecificAttribute	529	79	Ascend-Client-Secondary-WINS	ipaddr
        VendorSpecificAttribute	529	80	Ascend-Client-Assign-WINS	integer
        VendorSpecificAttribute	529	81	Ascend-Auth-Type	integer
        VendorSpecificAttribute	529	82	Ascend-Port-Redir-Protocol	integer
        VendorSpecificAttribute	529	83	Ascend-Port-Redir-Portnum	integer
        VendorSpecificAttribute	529	84	Ascend-Port-Redir-Server	ipaddr
        VendorSpecificAttribute	529	85	Ascend-IP-Pool-Chaining	integer
        VendorSpecificAttribute	529	86	Ascend-Owner-IP-Addr	ipaddr
        VendorSpecificAttribute	529	87	Ascend-IP-TOS	integer
        VendorSpecificAttribute	529	88	Ascend-IP-TOS-Precedence	integer
        VendorSpecificAttribute	529	89	Ascend-IP-TOS-Apply-To	integer
        VendorSpecificAttribute	529	90	Ascend-Filter	string
        VendorSpecificAttribute	529	91	Ascend-Telnet-Profile	string
        VendorSpecificAttribute	529	92	Ascend-Dsl-Rate-Type	integer
        VendorSpecificAttribute	529	93	Ascend-Redirect-Number	string
        VendorSpecificAttribute	529	94	Ascend-ATM-Vpi	integer
        VendorSpecificAttribute	529	95	Ascend-ATM-Vci	integer
        VendorSpecificAttribute	529	96	Ascend-Source-IP-Check	integer
        VendorSpecificAttribute	529	97	Ascend-Dsl-Rate-Mode	integer
        VendorSpecificAttribute	529	98	Ascend-Dsl-Upstream-Limit	integer
        VendorSpecificAttribute	529	99	Ascend-Dsl-Downstream-Limit	integer
        VendorSpecificAttribute	529	100	Ascend-Dsl-CIR-Recv-Limit	integer
        VendorSpecificAttribute	529	101	Ascend-Dsl-CIR-Xmit-Limit	integer
        VendorSpecificAttribute	529	102	Ascend-VRouter-Name	string
        VendorSpecificAttribute	529	103	Ascend-Source-Auth	string
        VendorSpecificAttribute	529	104	Ascend-Private-Route	string
        VendorSpecificAttribute	529	105	Ascend-Numbering-Plan-ID	integer
        VendorSpecificAttribute	529	106	Ascend-FR-Link-Status-DLCI	integer
        VendorSpecificAttribute	529	107	Ascend-Calling-Subaddress	string
        VendorSpecificAttribute	529	108	Ascend-Callback-Delay	integer
        VendorSpecificAttribute	529	109	Ascend-Endpoint-Disc	string
        VendorSpecificAttribute	529	110	Ascend-Remote-FW	string
        VendorSpecificAttribute	529	111	Ascend-Multicast-GLeave-Delay	integer
        VendorSpecificAttribute	529	112	Ascend-CBCP-Enable	integer
        VendorSpecificAttribute	529	113	Ascend-CBCP-Mode	integer
        VendorSpecificAttribute	529	114	Ascend-CBCP-Delay	integer
        VendorSpecificAttribute	529	115	Ascend-CBCP-Trunk-Group	integer
        VendorSpecificAttribute	529	116	Ascend-Appletalk-Route	string
        VendorSpecificAttribute	529	117	Ascend-Appletalk-Peer-Mode	integer
        VendorSpecificAttribute	529	118	Ascend-Route-Appletalk	integer
        VendorSpecificAttribute	529	119	Ascend-FCP-Parameter	string
        VendorSpecificAttribute	529	120	Ascend-Modem-PortNo	integer
        VendorSpecificAttribute	529	121	Ascend-Modem-SlotNo	integer
        VendorSpecificAttribute	529	122	Ascend-Modem-ShelfNo	integer
        VendorSpecificAttribute	529	123	Ascend-Call-Attempt-Limit	integer
        VendorSpecificAttribute	529	124	Ascend-Call-Block-Duration	integer
        VendorSpecificAttribute	529	125	Ascend-Maximum-Call-Duration	integer
        VendorSpecificAttribute	529	126	Ascend-Temporary-Rtes	integer
        VendorSpecificAttribute	529	127	Ascend-Tunneling-Protocol	integer
        VendorSpecificAttribute	529	128	Ascend-Shared-Profile-Enable	integer
        VendorSpecificAttribute	529	129	Ascend-Primary-Home-Agent	string
        VendorSpecificAttribute	529	130	Ascend-Secondary-Home-Agent	string
        VendorSpecificAttribute	529	131	Ascend-Dialout-Allowed	integer
        VendorSpecificAttribute	529	132	Ascend-Client-Gateway	ipaddr
        VendorSpecificAttribute	529	133	Ascend-BACP-Enable	integer
        VendorSpecificAttribute	529	134	Ascend-DHCP-Maximum-Leases	integer
        VendorSpecificAttribute	529	135	Ascend-Client-Primary-DNS	ipaddr
        VendorSpecificAttribute	529	136	Ascend-Client-Secondary-DNS	ipaddr
        VendorSpecificAttribute	529	137	Ascend-Client-Assign-DNS	integer
        VendorSpecificAttribute	529	138	Ascend-User-Acct-Type	integer
        VendorSpecificAttribute	529	139	Ascend-User-Acct-Host	ipaddr
        VendorSpecificAttribute	529	140	Ascend-User-Acct-Port	integer
        VendorSpecificAttribute	529	141	Ascend-User-Acct-Key	string
        VendorSpecificAttribute	529	142	Ascend-User-Acct-Base	integer
        VendorSpecificAttribute	529	143	Ascend-User-Acct-Time	integer
        VendorSpecificAttribute	529	144	Ascend-Assign-IP-Client	ipaddr
        VendorSpecificAttribute	529	145	Ascend-Assign-IP-Server	ipaddr
        VendorSpecificAttribute	529	146	Ascend-Assign-IP-Global-Pool	string
        VendorSpecificAttribute	529	147	Ascend-DHCP-Reply	integer
        VendorSpecificAttribute	529	148	Ascend-DHCP-Pool-Number	integer
        VendorSpecificAttribute	529	149	Ascend-Expect-Callback	integer
        VendorSpecificAttribute	529	150	Ascend-Event-Type	integer
        VendorSpecificAttribute	529	151	Ascend-Session-Svr-Key	string
        VendorSpecificAttribute	529	152	Ascend-Multicast-Rate-Limit	integer
        VendorSpecificAttribute	529	153	Ascend-IF-Netmask	ipaddr
        VendorSpecificAttribute	529	154	Ascend-Remote-Addr	ipaddr
        VendorSpecificAttribute	529	155	Ascend-Multicast-Client	integer
        VendorSpecificAttribute	529	156	Ascend-FR-Circuit-Name	string
        VendorSpecificAttribute	529	157	Ascend-FR-LinkUp	integer
        VendorSpecificAttribute	529	158	Ascend-FR-Nailed-Grp	integer
        VendorSpecificAttribute	529	159	Ascend-FR-Type	integer
        VendorSpecificAttribute	529	160	Ascend-FR-Link-Mgt	integer
        VendorSpecificAttribute	529	161	Ascend-FR-N391	integer
        VendorSpecificAttribute	529	162	Ascend-FR-DCE-N392	integer
        VendorSpecificAttribute	529	163	Ascend-FR-DTE-N392	integer
        VendorSpecificAttribute	529	164	Ascend-FR-DCE-N393	integer
        VendorSpecificAttribute	529	165	Ascend-FR-DTE-N393	integer
        VendorSpecificAttribute	529	166	Ascend-FR-T391	integer
        VendorSpecificAttribute	529	167	Ascend-FR-T392	integer
        VendorSpecificAttribute	529	168	Ascend-Bridge-Address	string
        VendorSpecificAttribute	529	169	Ascend-TS-Idle-Limit	integer
        VendorSpecificAttribute	529	170	Ascend-TS-Idle-Mode	integer
        VendorSpecificAttribute	529	171	Ascend-DBA-Monitor	integer
        VendorSpecificAttribute	529	172	Ascend-Base-Channel-Count	integer
        VendorSpecificAttribute	529	173	Ascend-Minimum-Channels	integer
        VendorSpecificAttribute	529	174	Ascend-IPX-Route	string
        VendorSpecificAttribute	529	175	Ascend-FT1-Caller	integer
        VendorSpecificAttribute	529	176	Ascend-Backup	string
        VendorSpecificAttribute	529	177	Ascend-Call-Type	integer
        VendorSpecificAttribute	529	178	Ascend-Group	string
        VendorSpecificAttribute	529	179	Ascend-FR-DLCI	integer
        VendorSpecificAttribute	529	180	Ascend-FR-Profile-Name	string
        VendorSpecificAttribute	529	181	Ascend-Ara-PW	string
        VendorSpecificAttribute	529	182	Ascend-IPX-Node-Addr	string
        VendorSpecificAttribute	529	183	Ascend-Home-Agent-IP-Addr	ipaddr
        VendorSpecificAttribute	529	184	Ascend-Home-Agent-Password	string
        VendorSpecificAttribute	529	185	Ascend-Home-Network-Name	string
        VendorSpecificAttribute	529	186	Ascend-Home-Agent-UDP-Port	integer
        VendorSpecificAttribute	529	187	Ascend-Multilink-ID	integer
        VendorSpecificAttribute	529	188	Ascend-Num-In-Multilink	integer
        VendorSpecificAttribute	529	189	Ascend-First-Dest	ipaddr
        VendorSpecificAttribute	529	190	Ascend-Pre-Input-Octets	integer
        VendorSpecificAttribute	529	191	Ascend-Pre-Output-Octets	integer
        VendorSpecificAttribute	529	192	Ascend-Pre-Input-Packets	integer
        VendorSpecificAttribute	529	193	Ascend-Pre-Output-Packets	integer
        VendorSpecificAttribute	529	194	Ascend-Maximum-Time	integer
        VendorSpecificAttribute	529	195	Ascend-Disconnect-Cause	integer
        VendorSpecificAttribute	529	196	Ascend-Connect-Progress	integer
        VendorSpecificAttribute	529	197	Ascend-Data-Rate	integer
        VendorSpecificAttribute	529	198	Ascend-PreSession-Time	integer
        VendorSpecificAttribute	529	199	Ascend-Token-Idle	integer
        VendorSpecificAttribute	529	200	Ascend-Token-Immediate	integer
        VendorSpecificAttribute	529	201	Ascend-Require-Auth	integer
        VendorSpecificAttribute	529	202	Ascend-Number-Sessions	string
        VendorSpecificAttribute	529	203	Ascend-Authen-Alias	string
        VendorSpecificAttribute	529	204	Ascend-Token-Expiry	integer
        VendorSpecificAttribute	529	205	Ascend-Menu-Selector	string
        VendorSpecificAttribute	529	206	Ascend-Menu-Item	string
        VendorSpecificAttribute	529	207	Ascend-PW-Warntime	integer
        VendorSpecificAttribute	529	208	Ascend-PW-Lifetime	integer
        VendorSpecificAttribute	529	209	Ascend-IP-Direct	ipaddr
        VendorSpecificAttribute	529	210	Ascend-PPP-VJ-Slot-Comp	integer
        VendorSpecificAttribute	529	211	Ascend-PPP-VJ-1172	integer
        VendorSpecificAttribute	529	212	Ascend-PPP-Async-Map	integer
        VendorSpecificAttribute	529	213	Ascend-Third-Prompt	string
        VendorSpecificAttribute	529	214	Ascend-Send-Secret	string
        VendorSpecificAttribute	529	215	Ascend-Receive-Secret	string
        VendorSpecificAttribute	529	216	Ascend-IPX-Peer-Mode	integer
        VendorSpecificAttribute	529	217	Ascend-IP-Pool-Definition	string
        VendorSpecificAttribute	529	218	Ascend-Assign-IP-Pool	integer
        VendorSpecificAttribute	529	219	Ascend-FR-Direct	integer
        VendorSpecificAttribute	529	220	Ascend-FR-Direct-Profile	string
        VendorSpecificAttribute	529	221	Ascend-FR-Direct-DLCI	integer
        VendorSpecificAttribute	529	222	Ascend-Handle-IPX	integer
        VendorSpecificAttribute	529	223	Ascend-Netware-timeout	integer
        VendorSpecificAttribute	529	224	Ascend-IPX-Alias	integer
        VendorSpecificAttribute	529	225	Ascend-Metric	integer
        VendorSpecificAttribute	529	226	Ascend-PRI-Number-Type	integer
        VendorSpecificAttribute	529	227	Ascend-Dial-Number	string
        VendorSpecificAttribute	529	228	Ascend-Route-IP	integer
        VendorSpecificAttribute	529	229	Ascend-Route-IPX	integer
        VendorSpecificAttribute	529	230	Ascend-Bridge	integer
        VendorSpecificAttribute	529	231	Ascend-Send-Auth	integer
        VendorSpecificAttribute	529	232	Ascend-Send-Passwd	string
        VendorSpecificAttribute	529	233	Ascend-Link-Compression	integer
        VendorSpecificAttribute	529	234	Ascend-Target-Util	integer
        VendorSpecificAttribute	529	235	Ascend-Maximum-Channels	integer
        VendorSpecificAttribute	529	236	Ascend-Inc-Channel-Count	integer
        VendorSpecificAttribute	529	237	Ascend-Dec-Channel-Count	integer
        VendorSpecificAttribute	529	238	Ascend-Seconds-Of-History	integer
        VendorSpecificAttribute	529	239	Ascend-History-Weigh-Type	integer
        VendorSpecificAttribute	529	240	Ascend-Add-Seconds	integer
        VendorSpecificAttribute	529	241	Ascend-Remove-Seconds	integer
        VendorSpecificAttribute	529	242	Ascend-Data-Filter	abinary
        VendorSpecificAttribute	529	243	Ascend-Call-Filter	abinary
        VendorSpecificAttribute	529	244	Ascend-Idle-Limit	integer
        VendorSpecificAttribute	529	245	Ascend-Preempt-Limit	integer
        VendorSpecificAttribute	529	246	Ascend-Callback	integer
        VendorSpecificAttribute	529	247	Ascend-Data-Svc	integer
        VendorSpecificAttribute	529	248	Ascend-Force-56	integer
        VendorSpecificAttribute	529	249	Ascend-Billing-Number	string
        VendorSpecificAttribute	529	250	Ascend-Call-By-Call	integer
        VendorSpecificAttribute	529	251	Ascend-Transit-Number	string
        VendorSpecificAttribute	529	252	Ascend-Host-Info	string
        VendorSpecificAttribute	529	253	Ascend-PPP-Address	ipaddr
        VendorSpecificAttribute	529	254	Ascend-MPP-Idle-Percent	integer
        VendorSpecificAttribute	529	255	Ascend-Xmit-Rate	integer

        # VendorId 710
        VendorSpecificAttribute	710	0	Breezecom-Attr0	string
        VendorSpecificAttribute	710	1	Breezecom-Attr1	string
        VendorSpecificAttribute	710	2	Breezecom-Attr2	string
        VendorSpecificAttribute	710	3	Breezecom-Attr3	string
        VendorSpecificAttribute	710	4	Breezecom-Attr4	string
        VendorSpecificAttribute	710	5	Breezecom-Attr5	string
        VendorSpecificAttribute	710	6	Breezecom-Attr6	string
        VendorSpecificAttribute	710	7	Breezecom-Attr7	string
        VendorSpecificAttribute	710	8	Breezecom-Attr8	string
        VendorSpecificAttribute	710	9	Breezecom-Attr9	string
        VendorSpecificAttribute	710	10	Breezecom-Attr10	string
        VendorSpecificAttribute	710	11	Breezecom-Attr11	string

        # VendorId 762
        VendorSpecificAttribute	762	151	KarlNet-TurboCell-Name	string
        VendorSpecificAttribute	762	152	KarlNet-TurboCell-TxRate	integer
        VendorSpecificAttribute	762	153	KarlNet-TurboCell-OpState	integer
        VendorSpecificAttribute	762	154	KarlNet-TurboCell-OpMode	integer

        # VendorId 1584
        VendorSpecificAttribute	1584	28	Annex-IP-Filter	string
        VendorSpecificAttribute	1584	29	Annex-CLI-Command	string
        VendorSpecificAttribute	1584	30	Annex-CLI-Filter	string
        VendorSpecificAttribute	1584	31	Annex-Host-Restrict	string
        VendorSpecificAttribute	1584	32	Annex-Host-Allow	string
        VendorSpecificAttribute	1584	33	Annex-Product-Name	string
        VendorSpecificAttribute	1584	34	Annex-SW-Version	string
        VendorSpecificAttribute	1584	35	Annex-Local-IP-Address	ipaddr
        VendorSpecificAttribute	1584	36	Annex-Callback-Portlist	integer
        VendorSpecificAttribute	1584	37	Annex-Sec-Profile-Index	integer
        VendorSpecificAttribute	1584	38	Annex-Tunnel-Authen-Type	integer
        VendorSpecificAttribute	1584	39	Annex-Tunnel-Authen-Mode	integer
        VendorSpecificAttribute	1584	40	Annex-Authen-Servers	string
        VendorSpecificAttribute	1584	41	Annex-Acct-Servers	string
        VendorSpecificAttribute	1584	42	Annex-User-Server-Location	integer
        VendorSpecificAttribute	1584	43	Annex-Local-Username	string
        VendorSpecificAttribute	1584	44	Annex-System-Disc-Reason	integer
        VendorSpecificAttribute	1584	45	Annex-Modem-Disc-Reason	integer
        VendorSpecificAttribute	1584	46	Annex-Disconnect-Reason	integer
        VendorSpecificAttribute	1584	47	Annex-Addr-Resolution-Protocol	integer
        VendorSpecificAttribute	1584	48	Annex-Addr-Resolution-Servers	string
        VendorSpecificAttribute	1584	49	Annex-Domain-Name	string
        VendorSpecificAttribute	1584	50	Annex-Transmit-Speed	integer
        VendorSpecificAttribute	1584	51	Annex-Receive-Speed	integer
        VendorSpecificAttribute	1584	52	Annex-Input-Filter	string
        VendorSpecificAttribute	1584	53	Annex-Output-Filter	string
        VendorSpecificAttribute	1584	54	Annex-Primary-DNS-Server	ipaddr
        VendorSpecificAttribute	1584	55	Annex-Secondary-DNS-Server	ipaddr
        VendorSpecificAttribute	1584	56	Annex-Primary-NBNS-Server	ipaddr
        VendorSpecificAttribute	1584	57	Annex-Secondary-NBNS-Server	ipaddr
        VendorSpecificAttribute	1584	58	Annex-Syslog-Tap	integer
        VendorSpecificAttribute	1584	59	Annex-Keypress-Timeout	integer
        VendorSpecificAttribute	1584	60	Annex-Unauthenticated-Time	integer
        VendorSpecificAttribute	1584	61	Annex-Re-CHAP-Timeout	integer
        VendorSpecificAttribute	1584	62	Annex-MRRU	integer
        VendorSpecificAttribute	1584	63	Annex-EDO	string
        VendorSpecificAttribute	1584	64	Annex-PPP-Trace-Level	integer
        VendorSpecificAttribute	1584	65	Annex-Pre-Input-Octets	integer
        VendorSpecificAttribute	1584	66	Annex-Pre-Output-Octets	integer
        VendorSpecificAttribute	1584	67	Annex-Pre-Input-Packets	integer
        VendorSpecificAttribute	1584	68	Annex-Pre-Output-Packets	integer
        VendorSpecificAttribute	1584	69	Annex-Connect-Progress	integer
        VendorSpecificAttribute	1584	70	Annex-First-Dest	ipaddr
        VendorSpecificAttribute	1584	71	Annex-PPP-Async-Map	integer
        VendorSpecificAttribute	1584	72	Annex-Multicast-Client	integer
        VendorSpecificAttribute	1584	73	Annex-Multicast-Rate-Limit	integer
        VendorSpecificAttribute	1584	74	Annex-Maximum-Call-Duration	integer
        VendorSpecificAttribute	1584	75	Annex-Multilink-ID	integer
        VendorSpecificAttribute	1584	76	Annex-Num-In-Multilink	integer
        VendorSpecificAttribute	1584	77	Annex-Inbound-Precedence	integer
        VendorSpecificAttribute	1584	78	Annex-Outbound-Precedence	integer
        VendorSpecificAttribute	1584	79	Annex-Secondary-Srv-Endpoint	string
        VendorSpecificAttribute	1584	80	Annex-Gwy-Selection-Mode	integer
        VendorSpecificAttribute	1584	81	Annex-Logical-Channel-Number	integer
        VendorSpecificAttribute	1584	82	Annex-Wan-Number	integer
        VendorSpecificAttribute	1584	83	Annex-Port	integer
        VendorSpecificAttribute	1584	85	Annex-Pool-Id	integer
        VendorSpecificAttribute	1584	86	Annex-Compression-Protocol	string
        VendorSpecificAttribute	1584	87	Annex-Transmitted-Packets	integer
        VendorSpecificAttribute	1584	88	Annex-Retransmitted-Packets	integer
        VendorSpecificAttribute	1584	89	Annex-Signal-to-Noise-Ratio	integer
        VendorSpecificAttribute	1584	90	Annex-Retrain-Requests-Sent	integer
        VendorSpecificAttribute	1584	91	Annex-Retrain-Requests-Rcvd	integer
        VendorSpecificAttribute	1584	92	Annex-Rate-Reneg-Req-Sent	integer
        VendorSpecificAttribute	1584	93	Annex-Rate-Reneg-Req-Rcvd	integer
        VendorSpecificAttribute	1584	94	Annex-Begin-Receive-Line-Level	integer
        VendorSpecificAttribute	1584	95	Annex-End-Receive-Line-Level	integer
        VendorSpecificAttribute	1584	96	Annex-Begin-Modulation	string
        VendorSpecificAttribute	1584	97	Annex-Error-Correction-Prot	string
        VendorSpecificAttribute	1584	98	Annex-End-Modulation	string
        VendorSpecificAttribute	1584	100	Bay-User-Level	integer
        VendorSpecificAttribute	1584	101	Bay-Audit-Level	integer

        # VendorId 1751
        VendorSpecificAttribute	1751	1	Lucent-Vendor-Specific	string

        # VendorId 1872
        VendorSpecificAttribute	1872	26	Alteon-Service-Type	integer

        # VendorId 1916
        VendorSpecificAttribute	1916	201	Extreme-CLI-Authorization	integer
        VendorSpecificAttribute	1916	202	Extreme-Shell-Command	string
        VendorSpecificAttribute	1916	203	Extreme-Netlogin-Vlan	string
        VendorSpecificAttribute	1916	204	Extreme-Netlogin-Url	string
        VendorSpecificAttribute	1916	205	Extreme-Netlogin-Url-Desc	string
        VendorSpecificAttribute	1916	206	Extreme-Netlogin-Only	integer
        VendorSpecificAttribute	1916	208	Extreme-User-Location	string
        VendorSpecificAttribute	1916	209	Extreme-Netlogin-VLAN-Tag	integer

        # VendorId 1958
        VendorSpecificAttribute	1958	5	RedCreek-Tunneled-IP-Addr	ipaddr
        VendorSpecificAttribute	1958	6	RedCreek-Tunneled-IP-Netmask	ipaddr
        VendorSpecificAttribute	1958	7	RedCreek-Tunneled-Gateway	ipaddr
        VendorSpecificAttribute	1958	8	RedCreek-Tunneled-DNS-Server	string
        VendorSpecificAttribute	1958	9	RedCreek-Tunneled-WINS-Server1	string
        VendorSpecificAttribute	1958	10	RedCreek-Tunneled-WINS-Server2	string
        VendorSpecificAttribute	1958	11	RedCreek-Tunneled-HostName	string
        VendorSpecificAttribute	1958	12	RedCreek-Tunneled-DomainName	string
        VendorSpecificAttribute	1958	13	RedCreek-Tunneled-Search-List	string

        # VendorId 1991
        VendorSpecificAttribute	1991	1	foundry-privilege-level	integer
        VendorSpecificAttribute	1991	2	foundry-command-string	string
        VendorSpecificAttribute	1991	3	foundry-command-exception-flag	integer

        # VendorId 1996
        VendorSpecificAttribute	1996	1	CMTN-Client-DNS-Pri	ipaddr
        VendorSpecificAttribute	1996	2	CMTN-Client-DNS-Sec	ipaddr
        VendorSpecificAttribute	1996	3	CMTN-TVR-GATEWAY	ipaddr
        VendorSpecificAttribute	1996	4	CMTN-TVR-SUBNETMASK	ipaddr
        VendorSpecificAttribute	1996	5	CMTN-TVR-DIAG-PORT-IP	ipaddr
        VendorSpecificAttribute	1996	6	CMTN-Client-NBNS-Pri	ipaddr
        VendorSpecificAttribute	1996	7	CMTN-Client-NBNS-Sec	ipaddr
        VendorSpecificAttribute	1996	8	CMTN-Service-Profile-Id	string
        VendorSpecificAttribute	1996	9	CMTN-Client-GATEWAY-IP	ipaddr

        # VendorId 2011
        VendorSpecificAttribute	2011	1	Huawei-Input-Burst-Size	integer
        VendorSpecificAttribute	2011	2	Huawei-Input-Average-Rate	integer
        VendorSpecificAttribute	2011	4	Huawei-Output-Burst-Size	integer
        VendorSpecificAttribute	2011	5	Huawei-Output-Average-Rate	integer
        VendorSpecificAttribute	2011	15	Huawei-Remanent-Volume	integer
        VendorSpecificAttribute	2011	22	Huawei-Priority	integer
        VendorSpecificAttribute	2011	27	Huawei-PortalURL	string
        VendorSpecificAttribute	2011	28	Huawei-FTP-Directory	string
        VendorSpecificAttribute	2011	29	Huawei-Exec-Privilege	integer
        VendorSpecificAttribute	2011	59	Huawei-Startup-Stamp	integer
        VendorSpecificAttribute	2011	60	Huawei-IPHost-Addr	string
        VendorSpecificAttribute	2011	85	Huawei-HW-Portal-Mode	integer
        VendorSpecificAttribute	2011	88	Huawei-Framed-Pool	string
        VendorSpecificAttribute	2011	92	Huawei-Layer4-Session-Limit	integer
        VendorSpecificAttribute	2011	93	Huawei-Multicast-Profile	string
        VendorSpecificAttribute	2011	94	Huawei-VPN-Instance	string
        VendorSpecificAttribute	2011	95	Huawei-Policy-Name	string
        VendorSpecificAttribute	2011	96	Huawei-Tunnel-Group-Name	string
        VendorSpecificAttribute	2011	135	Huawei-Primary-DNS	ipaddr
        VendorSpecificAttribute	2011	136	Huawei-Secondary-DNS	ipaddr
        VendorSpecificAttribute	2011	138	Huawei-Domain-Name	string
        VendorSpecificAttribute	2011	254	Huawei-Version	string
        VendorSpecificAttribute	2011	255	Huawei-Product-ID	string

        # VendorId 2323
        VendorSpecificAttribute	2323	5	User-Default-Gateway	ipaddr
        VendorSpecificAttribute	2323	6	VPN-DNS1	ipaddr
        VendorSpecificAttribute	2323	7	VPN-DNS1-LC	string
        VendorSpecificAttribute	2323	8	VPN-DNS2	ipaddr
        VendorSpecificAttribute	2323	9	VPN-DNS2-LC	string
        VendorSpecificAttribute	2323	16	VPN-DHCP1	ipaddr
        VendorSpecificAttribute	2323	17	VPN-DHCP1-LC	string
        VendorSpecificAttribute	2323	18	VPN-DHCP2	ipaddr
        VendorSpecificAttribute	2323	19	VPN-DHCP2-LC	string
        VendorSpecificAttribute	2323	20	Target-VPN	string
        VendorSpecificAttribute	2323	30	User-Mac-Address	integer
        VendorSpecificAttribute	2323	42	Input-Octets-Diff	integer
        VendorSpecificAttribute	2323	43	Output-Octets-Diff	integer
        VendorSpecificAttribute	2323	44	Belonging-Session	string
        VendorSpecificAttribute	2323	66	Tunnel-Clinet-LC	octet
        VendorSpecificAttribute	2323	81	Carrier-VPN	octet
        VendorSpecificAttribute	2323	91	TOS	integer
        VendorSpecificAttribute	2323	151	Multicast-Client-Allowed	integer
        VendorSpecificAttribute	2323	240	Statistics1	octet

        # VendorId 2334
        VendorSpecificAttribute	2334	1	Packeteer-AVPair	string

        # VendorId 2352
        VendorSpecificAttribute	2352	1	RB-Client-DNS-Pri	ipaddr
        VendorSpecificAttribute	2352	2	RB-Client-DNS-Sec	ipaddr
        VendorSpecificAttribute	2352	3	RB-DHCP-Max-Leases	integer
        VendorSpecificAttribute	2352	4	RB-Context-Name	string
        VendorSpecificAttribute	2352	5	RB-Bridge-Group	string
        VendorSpecificAttribute	2352	6	RB-BG-Aging-Time	string
        VendorSpecificAttribute	2352	7	RB-BG-Path-Cost	string
        VendorSpecificAttribute	2352	8	RB-BG-Span-Dis	string
        VendorSpecificAttribute	2352	9	RB-BG-Trans-BPDU	string
        VendorSpecificAttribute	2352	10	RB-Rate-Limit-Rate	integer
        VendorSpecificAttribute	2352	11	RB-Rate-Limit-Burst	integer
        VendorSpecificAttribute	2352	12	RB-Police-Rate	integer
        VendorSpecificAttribute	2352	13	RB-Police-Burst	integer
        VendorSpecificAttribute	2352	14	RB-Source-Validation	integer
        VendorSpecificAttribute	2352	15	RB-Tunnel-Domain	tagged-integer
        VendorSpecificAttribute	2352	16	RB-Tunnel-Local-Name	tagged-string
        VendorSpecificAttribute	2352	17	RB-Tunnel-Remote-Name	tagged-string
        VendorSpecificAttribute	2352	18	RB-Tunnel-Function	tagged-integer
        VendorSpecificAttribute	2352	19	RB-Tunnel-Flow-Control	tagged-integer
        VendorSpecificAttribute	2352	20	RB-Tunnel-Static	tagged-integer
        VendorSpecificAttribute	2352	21	RB-Tunnel-Max-Sessions	tagged-integer
        VendorSpecificAttribute	2352	22	RB-Tunnel-Max-Tunnels	tagged-integer
        VendorSpecificAttribute	2352	23	RB-Tunnel-Session-Auth	tagged-integer
        VendorSpecificAttribute	2352	24	RB-Tunnel-Window	tagged-integer
        VendorSpecificAttribute	2352	25	RB-Tunnel-Retransmit	tagged-integer
        VendorSpecificAttribute	2352	26	RB-Tunnel-Cmd-Timeout	tagged-integer
        VendorSpecificAttribute	2352	27	RB-PPPOE-URL	tagged-string
        VendorSpecificAttribute	2352	28	RB-PPPOE-MOTM	tagged-string
        VendorSpecificAttribute	2352	29	RB-Tunnel-Group	tagged-integer
        VendorSpecificAttribute	2352	30	RB-Tunnel-Context	tagged-string
        VendorSpecificAttribute	2352	31	RB-Tunnel-Algorithm	tagged-integer
        VendorSpecificAttribute	2352	32	RB-Tunnel-Deadtime	tagged-integer
        VendorSpecificAttribute	2352	33	RB-Mcast-Send	integer
        VendorSpecificAttribute	2352	34	RB-Mcast-Receive	integer
        VendorSpecificAttribute	2352	35	RB-Mcast-MaxGroups	integer
        VendorSpecificAttribute	2352	36	RB-Ip-Address-Pool-Name	string
        VendorSpecificAttribute	2352	37	RB-Tunnel-DNIS	tagged-integer
        VendorSpecificAttribute	2352	38	RB-Medium-Type	integer
        VendorSpecificAttribute	2352	39	RB-PVC-Encapsulation-Type	integer
        VendorSpecificAttribute	2352	40	RB-PVC-Profile-Name	string
        VendorSpecificAttribute	2352	41	RB-PVC-Circuit-Padding	integer
        VendorSpecificAttribute	2352	42	RB-Bind-Type	integer
        VendorSpecificAttribute	2352	43	RB-Bind-Auth-Protocol	integer
        VendorSpecificAttribute	2352	44	RB-Bind-Auth-Max-Sessions	integer
        VendorSpecificAttribute	2352	45	RB-Bind-Bypass-Bypass	string
        VendorSpecificAttribute	2352	46	RB-Bind-Auth-Context	string
        VendorSpecificAttribute	2352	47	RB-Bind-Auth-Service-Grp	string
        VendorSpecificAttribute	2352	48	RB-Bind-Bypass-Context	string
        VendorSpecificAttribute	2352	49	RB-Bind-Int-Context	string
        VendorSpecificAttribute	2352	50	RB-Bind-Tun-Context	string
        VendorSpecificAttribute	2352	51	RB-Bind-Ses-Context	string
        VendorSpecificAttribute	2352	52	RB-Bind-Dot1q-Slot	integer
        VendorSpecificAttribute	2352	53	RB-Bind-Dot1q-Port	integer
        VendorSpecificAttribute	2352	54	RB-Bind-Dot1q-Vlan-Tag-Id	integer
        VendorSpecificAttribute	2352	55	RB-Bind-Int-Interface-Name	string
        VendorSpecificAttribute	2352	56	RB-Bind-L2TP-Tunnel-Name	string
        VendorSpecificAttribute	2352	57	RB-Bind-L2TP-Flow-Control	integer
        VendorSpecificAttribute	2352	58	RB-Bind-Sub-User-At-Context	string
        VendorSpecificAttribute	2352	59	RB-Bind-Sub-Password	string
        VendorSpecificAttribute	2352	60	RB-Ip-Host-Addr	string
        VendorSpecificAttribute	2352	61	RB-IP-TOS-Field	integer
        VendorSpecificAttribute	2352	62	RB-NAS-Real-Port	integer
        VendorSpecificAttribute	2352	63	RB-Tunnel-Session-Auth-Ctx	tagged-string
        VendorSpecificAttribute	2352	64	RB-Tunnel-Session-Auth-Service-Grp	tagged-string
        VendorSpecificAttribute	2352	65	RB-Tunnel-Rate-Limit-Rate	tagged-integer
        VendorSpecificAttribute	2352	66	RB-Tunnel-Rate-Limit-Burst	tagged-integer
        VendorSpecificAttribute	2352	67	RB-Tunnel-Police-Rate	tagged-integer
        VendorSpecificAttribute	2352	68	RB-Tunnel-Police-Burst	tagged-integer
        VendorSpecificAttribute	2352	69	RB-Tunnel-L2F-Second-Password	tagged-string
        VendorSpecificAttribute	2352	70	RB-ACL-Definition	string
        VendorSpecificAttribute	2352	71	RB-PPPoE-IP-Route-Add	string
        VendorSpecificAttribute	2352	72	RB-TTY-Level-Max	integer
        VendorSpecificAttribute	2352	73	RB-TTY-Level-Start	integer
        VendorSpecificAttribute	2352	76	RB-Bind-DHCP-Context	string
        VendorSpecificAttribute	2352	77	RB-Tunnel-Mobile-Group	tagged-string
        VendorSpecificAttribute	2352	78	RB-Tunnel-Client-VPN	tagged-string
        VendorSpecificAttribute	2352	79	RB-Tunnel-Server-VPN	tagged-string
        VendorSpecificAttribute	2352	84	RB-PPP-Compression	integer
        VendorSpecificAttribute	2352	85	RB-Tunnel-Hello-Timer	tagged-integer
        VendorSpecificAttribute	2352	86	RB-NAS-Port	string
        VendorSpecificAttribute	2352	87	RB-QoS-Policing-Profile-Name	string
        VendorSpecificAttribute	2352	88	RB-QoS-Metering-Profile-Name	string
        VendorSpecificAttribute	2352	89	RB-QoS-Pq	integer
        VendorSpecificAttribute	2352	90	RB-IGMP-Service-Profile-Name	string
        VendorSpecificAttribute	2352	91	RB-Subscriber-Profile-Name	string
        VendorSpecificAttribute	2352	92	RB-Forward-Policy	string
        VendorSpecificAttribute	2352	93	RB-Remote-Port	string
        VendorSpecificAttribute	2352	94	RB-Reauth	string
        VendorSpecificAttribute	2352	95	RB-Reauth-More	integer
        VendorSpecificAttribute	2352	98	RB-Platform-Type	string
        VendorSpecificAttribute	2352	99	RB-Client-NBNS-Pri	ipaddr
        VendorSpecificAttribute	2352	100	RB-Client-NBNS-Sec	ipaddr
        VendorSpecificAttribute	2352	101	RB-Shaping-Profile-Name	string
        VendorSpecificAttribute	2352	103	RB-Bridge-Profile-Name	string
        VendorSpecificAttribute	2352	104	RB-IP-Interface	string
        VendorSpecificAttribute	2352	105	RB-NAT-Policy-Name	string
        VendorSpecificAttribute	2352	107	RB-HTTP-Redirect-Profile-Name	string
        VendorSpecificAttribute	2352	112	RB-OS-Version	string
        VendorSpecificAttribute	2352	113	RB-Session-Traffic-Limit	string
        VendorSpecificAttribute	2352	114	RB-QoS-Reference	string
        VendorSpecificAttribute	2352	128	RB-Acct-Input-Octets-64	integer8
        VendorSpecificAttribute	2352	129	RB-Acct-Output-Octets-64	integer8
        VendorSpecificAttribute	2352	130	RB-Acct-Input-Packets-64	integer8
        VendorSpecificAttribute	2352	131	RB-Acct-Output-Packets-64	integer8
        VendorSpecificAttribute	2352	132	RB-Assigned-IP-Address	ipaddr
        VendorSpecificAttribute	2352	133	RB-Acct-Mcast-In-Octets-64	integer8
        VendorSpecificAttribute	2352	134	RB-Acct-Mcast-Out-Octets-64	integer8
        VendorSpecificAttribute	2352	135	RB-Acct-Mcast-In-Packets-64	integer8
        VendorSpecificAttribute	2352	136	RB-Acct-Mcast-Out-Packets-64	integer8
        VendorSpecificAttribute	2352	137	RB-LAC-Port	integer
        VendorSpecificAttribute	2352	138	RB-LAC-Real-Port	integer
        VendorSpecificAttribute	2352	139	RB-LAC-Port-Type	integer
        VendorSpecificAttribute	2352	140	RB-LAC-Real-Port-Type	integer
        VendorSpecificAttribute	2352	141	RB-Acct-Dyn-Ac-Ent	string
        VendorSpecificAttribute	2352	142	RB-Session_Error_Code	integer
        VendorSpecificAttribute	2352	143	RB-Session_Error_Msg	string
        VendorSpecificAttribute	2352	144	RB-Acct-Update-Reason	integer
        VendorSpecificAttribute	2352	145	RB-Acct-MAC-Addr	string
        VendorSpecificAttribute	2352	146	RB-Acct-VLAN-Id	string
        VendorSpecificAttribute	2352	147	RB-Acct-Mcast-In-Octets	integer
        VendorSpecificAttribute	2352	148	RB-Acct-Mcast-Out-Octets	integer
        VendorSpecificAttribute	2352	149	RB-Acct-Mcast-In-Packets	integer
        VendorSpecificAttribute	2352	150	RB-Acct-Mcast-Out-Packet	integer
        VendorSpecificAttribute	2352	151	RB-Reauth-Session-Id	string

        # VendorId 2526
        VendorSpecificAttribute	2526	1	Ipass-Country-Code	string
        VendorSpecificAttribute	2526	2	Ipass-Media-Access-Type	string
        VendorSpecificAttribute	2526	3	Ipass-Location-Description	string

        # VendorId 2636
        VendorSpecificAttribute	2636	1	Juniper-Local-User-Name	string
        VendorSpecificAttribute	2636	2	Juniper-Allow-Commands	string
        VendorSpecificAttribute	2636	3	Juniper-Deny-Commands	string

        # VendorId 2637
        VendorSpecificAttribute	2637	1	CVX-Identification	string
        VendorSpecificAttribute	2637	2	CVX-VPOP-ID	integer
        VendorSpecificAttribute	2637	3	CVX-SS7-Session-ID-Type	integer
        VendorSpecificAttribute	2637	4	CVX-Radius-Redirect	integer
        VendorSpecificAttribute	2637	5	CVX-IPSVC-AZNLVL	integer
        VendorSpecificAttribute	2637	6	CVX-IPSVC-Mask	integer
        VendorSpecificAttribute	2637	7	CVX-Multilink-Match-Info	integer
        VendorSpecificAttribute	2637	8	CVX-Multilink-Group-Number	integer
        VendorSpecificAttribute	2637	9	CVX-PPP-Log-Mask	integer
        VendorSpecificAttribute	2637	10	CVX-Modem-Begin-Modulation	string
        VendorSpecificAttribute	2637	11	CVX-Modem-End-Modulation	string
        VendorSpecificAttribute	2637	12	CVX-Modem-Error-Correction	string
        VendorSpecificAttribute	2637	13	CVX-Modem-Data-Compression	string
        VendorSpecificAttribute	2637	14	CVX-Modem-Tx-Packets	integer
        VendorSpecificAttribute	2637	15	CVX-Modem-ReTx-Packets	integer
        VendorSpecificAttribute	2637	16	CVX-Modem-SNR	integer
        VendorSpecificAttribute	2637	17	CVX-Modem-Local-Retrains	integer
        VendorSpecificAttribute	2637	18	CVX-Modem-Remote-Retrains	integer
        VendorSpecificAttribute	2637	19	CVX-Modem-Local-Rate-Negs	integer
        VendorSpecificAttribute	2637	20	CVX-Modem-Remote-Rate-Negs	integer
        VendorSpecificAttribute	2637	21	CVX-Modem-Begin-Recv-Line-Lvl	integer
        VendorSpecificAttribute	2637	22	CVX-Modem-End-Recv-Line-Lvl	integer
        VendorSpecificAttribute	2637	23	CVX-Terminate-Component	integer
        VendorSpecificAttribute	2637	24	CVX-Terminate-Cause	integer
        VendorSpecificAttribute	2637	25	CVX-Reject-Reason	integer
        VendorSpecificAttribute	2637	135	CVX-Ascend-Primary-DNS	ipaddr
        VendorSpecificAttribute	2637	136	CVX-Ascend-Secondary-DNS	ipaddr
        VendorSpecificAttribute	2637	137	CVX-Ascend-Client-Assign-DNS	integer
        VendorSpecificAttribute	2637	150	CVX-Ascend-Event-Type	integer
        VendorSpecificAttribute	2637	152	CVX-Ascend-Multicast-Rate-Limit	integer
        VendorSpecificAttribute	2637	155	CVX-Ascend-Multicast-Client	integer
        VendorSpecificAttribute	2637	195	CVX-Ascend-Disconnect-Cause	integer
        VendorSpecificAttribute	2637	197	CVX-Ascend-Data-Rate	integer
        VendorSpecificAttribute	2637	198	CVX-Ascend-PreSession-Time	integer
        VendorSpecificAttribute	2637	218	CVX-Ascend-Assign-IP-Pool	integer
        VendorSpecificAttribute	2637	235	CVX-Ascend-Maximum-Channels	integer
        VendorSpecificAttribute	2637	242	CVX-Ascend-Data-Filter	string
        VendorSpecificAttribute	2637	244	CVX-Ascend-Idle-Limit	integer
        VendorSpecificAttribute	2637	253	CVX-Ascend-PPP-Address	ipaddr
        VendorSpecificAttribute	2637	255	CVX-Ascend-Xmit-Rate	integer

        # VendorId 2937
        VendorSpecificAttribute	2937	22	DTAG-Proxy-IP-Adr	ipaddr
        VendorSpecificAttribute	2937	23	DTAG-Proxy-Receive-Time	integer

        # VendorId 3041
        VendorSpecificAttribute	3041	5	AAT-Client-Primary-DNS	ipaddr
        VendorSpecificAttribute	3041	6	AAT-Client-Primary-WINS-NBNS	ipaddr
        VendorSpecificAttribute	3041	7	AAT-Client-Secondary-WINS-NBNS	ipaddr
        VendorSpecificAttribute	3041	8	AAT-Client-Primary-DNS	ipaddr
        VendorSpecificAttribute	3041	9	AAT-PPP-Address	ipaddr
        VendorSpecificAttribute	3041	21	AAT-ATM-Direct	string
        VendorSpecificAttribute	3041	22	AAT-IP-TOS	integer
        VendorSpecificAttribute	3041	23	AAT-IP-TOS-Precedence	integer
        VendorSpecificAttribute	3041	24	AAT-IP-TOS-Apply-To	integer
        VendorSpecificAttribute	3041	27	AAT-MCast-Client	integer
        VendorSpecificAttribute	3041	61	AAT-Vrouter-Name	string
        VendorSpecificAttribute	3041	62	AAT-Require-Auth	integer
        VendorSpecificAttribute	3041	63	AAT-IP-Pool-Definition	string
        VendorSpecificAttribute	3041	64	AAT-Assign-IP-Pool	integer
        VendorSpecificAttribute	3041	65	AAT-Data-Filter	string
        VendorSpecificAttribute	3041	66	AAT-Source-IP-Check	integer
        VendorSpecificAttribute	3041	128	AAT-ATM-VPI	integer
        VendorSpecificAttribute	3041	129	AAT-ATM-VCI	integer
        VendorSpecificAttribute	3041	130	AAT-Input-Octets-Diff	integer
        VendorSpecificAttribute	3041	131	AAT-Output-Octets-Diff	integer
        VendorSpecificAttribute	3041	132	AAT-User-MAC-Address	string
        VendorSpecificAttribute	3041	133	AAT-ATM-Traffic-Profile	string

        # VendorId 3076
        VendorSpecificAttribute	3076	1	Altiga-Access-Hours-G/U	string
        VendorSpecificAttribute	3076	2	Altiga-Simultaneous-Logins-G/U	integer
        VendorSpecificAttribute	3076	3	Altiga-Min-Password-Length-G	integer
        VendorSpecificAttribute	3076	4	Altiga-Allow-Alpha-Only-Passwords-G	integer
        VendorSpecificAttribute	3076	5	Altiga-Primary-DNS-G	ipaddr
        VendorSpecificAttribute	3076	6	Altiga-Secondary-DNS-G	ipaddr
        VendorSpecificAttribute	3076	7	Altiga-Primary-WINS-G	ipaddr
        VendorSpecificAttribute	3076	8	Altiga-Secondary-WINS-G	ipaddr
        VendorSpecificAttribute	3076	9	Altiga-SEP-Card-Assignment-G/U	integer
        VendorSpecificAttribute	3076	10	Altiga-Priority-on-SEP-G/U	integer
        VendorSpecificAttribute	3076	11	Altiga-Tunneling-Protocols-G/U	integer
        VendorSpecificAttribute	3076	12	Altiga-IPSec-Sec-Association-G/U	string
        VendorSpecificAttribute	3076	13	Altiga-IPSec-Authentication-G	integer
        VendorSpecificAttribute	3076	15	Altiga-IPSec-Banner-G	string
        VendorSpecificAttribute	3076	16	Altiga-IPSec-Allow-Passwd-Store-G/U	integer
        VendorSpecificAttribute	3076	17	Altiga-Use-Client-Address-G/U	integer
        VendorSpecificAttribute	3076	18	Altiga-PPTP-Min-Authentication-G/U	integer
        VendorSpecificAttribute	3076	19	Altiga-L2TP-Min-Authentication-G/U	integer
        VendorSpecificAttribute	3076	20	Altiga-PPTP-Encryption-G	integer
        VendorSpecificAttribute	3076	21	Altiga-L2TP-Encryption-G	integer
        VendorSpecificAttribute	3076	22	Altiga-Argument-Auth-Server-Type	integer
        VendorSpecificAttribute	3076	23	Altiga-Argument-Auth-Server-Password	string
        VendorSpecificAttribute	3076	24	Altiga-Argument-Request-Authenticator-Vector	string
        VendorSpecificAttribute	3076	25	Altiga-IPSec-L2L-Keepalives-G	integer
        VendorSpecificAttribute	3076	26	Altiga-IPSec-Group-Name	integer
        VendorSpecificAttribute	3076	27	Altiga-IPSec-Split-Tunnel-List-G	string
        VendorSpecificAttribute	3076	28	Altiga-IPSec-Default-Domain-G	string
        VendorSpecificAttribute	3076	29	Altiga-IPSec-Secondary-Domains-G	string
        VendorSpecificAttribute	3076	30	Altiga-IPSec-Tunnel-Type-G	integer
        VendorSpecificAttribute	3076	31	Altiga-IPSec-Mode-Config-G	integer
        VendorSpecificAttribute	3076	32	Altiga-Argument-Auth-Server-Priority	integer
        VendorSpecificAttribute	3076	33	Altiga-IPSec-User-Group-Lock-G	integer
        VendorSpecificAttribute	3076	34	Altiga-IPSec-Through-NAT	integer
        VendorSpecificAttribute	3076	35	Altiga-IPSec-Through-NAT-Port	integer
        VendorSpecificAttribute	3076	36	Altiga-IPSec-Banner-Part-2-G	string
        VendorSpecificAttribute	3076	37	Altiga-PPTP-MPPC-Compression	integer
        VendorSpecificAttribute	3076	38	Altiga-L2TP-MPPC-Compression	integer
        VendorSpecificAttribute	3076	39	Altiga-IPSec-IPComp	integer
        VendorSpecificAttribute	3076	40	Altiga-IPSec-IKE-Peer-ID-Check	integer
        VendorSpecificAttribute	3076	41	Altiga-IPSec-IKE-Keepalives	integer
        VendorSpecificAttribute	3076	42	Altiga-IPSec-Reauthentication-Rekey	integer
        VendorSpecificAttribute	3076	45	Altiga-Required-FW-Vendor-Code-G	integer
        VendorSpecificAttribute	3076	46	Altiga-Required-FW-Product-Code-G	integer
        VendorSpecificAttribute	3076	47	Altiga-Required-FW-Description-G	string
        VendorSpecificAttribute	3076	48	Altiga-Require-HW-Client-Auth-G	integer
        VendorSpecificAttribute	3076	49	Altiga-Require-Individual-User-Auth-G	integer
        VendorSpecificAttribute	3076	50	Altiga-User-Idle-Timeout-G	integer
        VendorSpecificAttribute	3076	51	Altiga-Cisco-IP-Phone-Bypass-G	integer
        VendorSpecificAttribute	3076	55	Altiga-IPSec-Split-Tunnel-Policy-G	integer
        VendorSpecificAttribute	3076	56	Altiga-Client-FW-Capability-G	integer
        VendorSpecificAttribute	3076	57	Altiga-Client-FW-Filter-Name-G	string
        VendorSpecificAttribute	3076	58	Altiga-Client-FW-Optional-G	integer
        VendorSpecificAttribute	3076	59	Altiga-IPSec-Backup-Server-Enabled-G	integer
        VendorSpecificAttribute	3076	60	Altiga-IPSec-Backup-Server-List-G	string
        VendorSpecificAttribute	3076	61	Altiga-DHCP-Network-Scope-G	ipaddr
        VendorSpecificAttribute	3076	62	Altiga-Intercept-DHCP-Config-Msg-G	integer
        VendorSpecificAttribute	3076	63	Altiga-MS-Client-Subnet-Mask-G	ipaddr
        VendorSpecificAttribute	3076	64	Altiga-Allow-Network-Ext-Mode-G	integer
        VendorSpecificAttribute	3076	65	Altiga-IPSec-Authorization-Type-G	integer
        VendorSpecificAttribute	3076	66	Altiga-IPSec-Authorization-Required-G	integer
        VendorSpecificAttribute	3076	67	Altiga-IPSec-DN-Field-G	string
        VendorSpecificAttribute	3076	68	Altiga-IPSec-Confidence-Level-G	integer
        VendorSpecificAttribute	3076	75	Altiga-LEAP-Bypass-G	integer
        VendorSpecificAttribute	3076	128	Altiga-Part-Primary-DHCP-G	ipaddr
        VendorSpecificAttribute	3076	129	Altiga-Part-Secondary-DHCP-G	ipaddr
        VendorSpecificAttribute	3076	131	Altiga-Part-Premise-Router-G	ipaddr
        VendorSpecificAttribute	3076	132	Altiga-Part-Max-Sessions-G	integer
        VendorSpecificAttribute	3076	133	Altiga-Part-Mobile-IP-Key-G	integer
        VendorSpecificAttribute	3076	134	Altiga-Part-Mobile-IP-Address-G	ipaddr
        VendorSpecificAttribute	3076	135	Altiga-General-Strip-Realm-G	integer
        VendorSpecificAttribute	3076	136	Altiga-Part-Strip-Realm-G	integer
        VendorSpecificAttribute	3076	137	Altiga-Part-Group-ID-G	integer

        # VendorId 3199
        VendorSpecificAttribute	3199	1	Shasta-User-Priv	integer
        VendorSpecificAttribute	3199	2	Shasta-Service-Profile	string
        VendorSpecificAttribute	3199	3	Shasta-VPN	string
        VendorSpecificAttribute	3199	4	Shasta-SGROUP	string
        VendorSpecificAttribute	3199	5	Shasta-L2TP-Tunset	string

        # VendorId 3224
        VendorSpecificAttribute	3224	1	NS-Admin-Privilege	integer
        VendorSpecificAttribute	3224	2	NS-Admin-Vsys-Name	string
        VendorSpecificAttribute	3224	3	NS-User-Group	string
        VendorSpecificAttribute	3224	4	NS-Primary-DNS-Server	ipaddr
        VendorSpecificAttribute	3224	5	NS-Secondary-DNS-Server	ipaddr
        VendorSpecificAttribute	3224	6	NS-Primary-WINS-Server	ipaddr
        VendorSpecificAttribute	3224	7	NS-Secondary-WINS-Server	ipaddr
        VendorSpecificAttribute	3224	8	NS-Version	string
        VendorSpecificAttribute	3224	200	NS-PRO-User-Group	string
        VendorSpecificAttribute	3224	201	NS-PRO-User-IKEID	string

        # VendorId 3309
        VendorSpecificAttribute	3309	1	Nomadix-Bw-Up	integer
        VendorSpecificAttribute	3309	2	Nomadix-Bw-Down	integer
        VendorSpecificAttribute	3309	3	Nomadix-URL-Redirection	string
        VendorSpecificAttribute	3309	4	Nomadix-IP-Upsell	integer
        VendorSpecificAttribute	3309	5	Nomadix-Expiration-Time	string
        VendorSpecificAttribute	3309	6	Nomadix-Subnet	string
        VendorSpecificAttribute	3309	7	Nomadix-MaxBytesUp	integer
        VendorSpecificAttribute	3309	8	Nomadix-MaxBytesDown	integer
        VendorSpecificAttribute	3309	9	Nomadix-EndofSession	integer
        VendorSpecificAttribute	3309	10	Nomadix-Logoff-URL	string
        VendorSpecificAttribute	3309	11	Nomadix-Net-VLAN	integer
        VendorSpecificAttribute	3309	12	Nomadix-Config-URL	string
        VendorSpecificAttribute	3309	13	Nomadix-Goodbye-URL	string

        # VendorId 3414
        VendorSpecificAttribute	3414	40	Ipass-3414-40	string
        VendorSpecificAttribute	3414	41	Ipass-3414-41	string
        VendorSpecificAttribute	3414	42	Ipass-3414-42	string
        VendorSpecificAttribute	3414	43	Ipass-3414-43	string

        # VendorId 3551
        VendorSpecificAttribute	3551	1	ST-Acct-VC-Connection-Id	string
        VendorSpecificAttribute	3551	2	ST-Service-Name	string
        VendorSpecificAttribute	3551	3	ST-Service-Domain	integer
        VendorSpecificAttribute	3551	4	ST-Policy-Name	string
        VendorSpecificAttribute	3551	5	ST-Primary-DNS-Server	ipaddr
        VendorSpecificAttribute	3551	6	ST-Secondary-DNS-Server	ipaddr
        VendorSpecificAttribute	3551	7	ST-Primary-NBNS-Server	ipaddr
        VendorSpecificAttribute	3551	8	ST-Secondary-NBNS-Server	ipaddr
        VendorSpecificAttribute	3551	9	ST-Physical-Port	integer
        VendorSpecificAttribute	3551	10	ST-Physical-Slot	integer
        VendorSpecificAttribute	3551	11	ST-Virtual-Path-ID	integer
        VendorSpecificAttribute	3551	12	ST-Virtual-Circuit-ID	integer
        VendorSpecificAttribute	3551	13	ST-Realm-Name	string

        # VendorId 3780
        VendorSpecificAttribute	3780	101	Level3-Data-Filters-1	string
        VendorSpecificAttribute	3780	102	Level3-Data-Filters-2	string
        VendorSpecificAttribute	3780	103	Level3-Tunnel-Backup	string
        VendorSpecificAttribute	3780	104	Level3-Tunnel-Password	string
        VendorSpecificAttribute	3780	201	Level3-Service-Area	string
        VendorSpecificAttribute	3780	202	Level3-Home-GW	string
        VendorSpecificAttribute	3780	203	Level3-Satellite	string

        # VendorId 4163
        VendorSpecificAttribute	4163	1	Quarry-Customer-Name	string
        VendorSpecificAttribute	4163	2	Quarry-Template-Name	string
        VendorSpecificAttribute	4163	3	Quarry-Param-Name-01	string
        VendorSpecificAttribute	4163	4	Quarry-Param-Name-02	string
        VendorSpecificAttribute	4163	5	Quarry-Param-Name-03	string
        VendorSpecificAttribute	4163	6	Quarry-Param-Name-04	string
        VendorSpecificAttribute	4163	7	Quarry-Param-Name-05	string
        VendorSpecificAttribute	4163	8	Quarry-Param-Name-06	string
        VendorSpecificAttribute	4163	9	Quarry-Param-Name-07	string
        VendorSpecificAttribute	4163	10	Quarry-Param-Name-08	string
        VendorSpecificAttribute	4163	11	Quarry-Param-Name-09	string
        VendorSpecificAttribute	4163	12	Quarry-Param-Name-10	string
        VendorSpecificAttribute	4163	13	Quarry-Param-Name-11	string
        VendorSpecificAttribute	4163	14	Quarry-Param-Name-12	string
        VendorSpecificAttribute	4163	15	Quarry-Param-Name-13	string
        VendorSpecificAttribute	4163	16	Quarry-Param-Name-14	string
        VendorSpecificAttribute	4163	17	Quarry-Param-Name-15	string
        VendorSpecificAttribute	4163	18	Quarry-Param-Name-16	string
        VendorSpecificAttribute	4163	19	Quarry-Param-Name-17	string
        VendorSpecificAttribute	4163	20	Quarry-Param-Name-18	string
        VendorSpecificAttribute	4163	21	Quarry-Param-Name-19	string
        VendorSpecificAttribute	4163	22	Quarry-Param-Name-20	string
        VendorSpecificAttribute	4163	23	Quarry-Param-Name-21	string
        VendorSpecificAttribute	4163	24	Quarry-Param-Name-22	string
        VendorSpecificAttribute	4163	25	Quarry-Param-Name-23	string
        VendorSpecificAttribute	4163	26	Quarry-Param-Name-24	string
        VendorSpecificAttribute	4163	27	Quarry-Param-Name-25	string
        VendorSpecificAttribute	4163	28	Quarry-Param-Val-01	string
        VendorSpecificAttribute	4163	29	Quarry-Param-Val-02	string
        VendorSpecificAttribute	4163	30	Quarry-Param-Val-03	string
        VendorSpecificAttribute	4163	31	Quarry-Param-Val-04	string
        VendorSpecificAttribute	4163	32	Quarry-Param-Val-05	string
        VendorSpecificAttribute	4163	33	Quarry-Param-Val-06	string
        VendorSpecificAttribute	4163	34	Quarry-Param-Val-07	string
        VendorSpecificAttribute	4163	35	Quarry-Param-Val-08	string
        VendorSpecificAttribute	4163	36	Quarry-Param-Val-09	string
        VendorSpecificAttribute	4163	37	Quarry-Param-Val-10	string
        VendorSpecificAttribute	4163	38	Quarry-Param-Val-11	string
        VendorSpecificAttribute	4163	39	Quarry-Param-Val-12	string
        VendorSpecificAttribute	4163	40	Quarry-Param-Val-13	string
        VendorSpecificAttribute	4163	41	Quarry-Param-Val-14	string
        VendorSpecificAttribute	4163	42	Quarry-Param-Val-15	string
        VendorSpecificAttribute	4163	43	Quarry-Param-Val-16	string
        VendorSpecificAttribute	4163	44	Quarry-Param-Val-17	string
        VendorSpecificAttribute	4163	45	Quarry-Param-Val-18	string
        VendorSpecificAttribute	4163	46	Quarry-Param-Val-19	string
        VendorSpecificAttribute	4163	47	Quarry-Param-Val-20	string
        VendorSpecificAttribute	4163	48	Quarry-Param-Val-21	string
        VendorSpecificAttribute	4163	49	Quarry-Param-Val-22	string
        VendorSpecificAttribute	4163	50	Quarry-Param-Val-23	string
        VendorSpecificAttribute	4163	51	Quarry-Param-Val-24	string
        VendorSpecificAttribute	4163	52	Quarry-Param-Val-25	string

        # VendorId 4846
        VendorSpecificAttribute	4846	261	Ascend-MOH-Timeout	integer

        # VendorId 4874
        VendorSpecificAttribute	4874	1	Unisphere-Virtual-Router	string
        VendorSpecificAttribute	4874	2	Unisphere-Local-Address-Pool	string
        VendorSpecificAttribute	4874	3	Unisphere-Local-Interface	string
        VendorSpecificAttribute	4874	4	Unisphere-Primary-Dns	ipaddr
        VendorSpecificAttribute	4874	5	Unisphere-Secondary-Dns	ipaddr
        VendorSpecificAttribute	4874	6	Unisphere-Primary-Wins	ipaddr
        VendorSpecificAttribute	4874	7	Unisphere-Secondary-Wins	ipaddr
        VendorSpecificAttribute	4874	8	Unisphere-Tunnel-Virtual-Router	string
        VendorSpecificAttribute	4874	9	Unisphere-Tunnel-Password	string
        VendorSpecificAttribute	4874	10	Unisphere-Ingress-Policy-Name	string
        VendorSpecificAttribute	4874	11	Unisphere-Egress-Policy-Name	string
        VendorSpecificAttribute	4874	12	Unisphere-Ingress-Statistics	integer
        VendorSpecificAttribute	4874	13	Unisphere-Egress-Statistics	integer
        VendorSpecificAttribute	4874	14	Unisphere-Service-Category	integer
        VendorSpecificAttribute	4874	15	Unisphere-pcr	integer
        VendorSpecificAttribute	4874	16	Unisphere-scr-Or-Cbr-Bit-Rate	integer
        VendorSpecificAttribute	4874	17	Unisphere-mbs	integer
        VendorSpecificAttribute	4874	18	Unisphere-Init-CLI-Access-Level	string
        VendorSpecificAttribute	4874	19	Unisphere-Allow-All-VR-Access	integer
        VendorSpecificAttribute	4874	20	Unisphere-Alt-CLI-Access-Level	string
        VendorSpecificAttribute	4874	21	Unisphere-Alt-CLI-VRouter-Name	string
        VendorSpecificAttribute	4874	22	Unisphere-SA-Validate	integer
        VendorSpecificAttribute	4874	23	Unisphere-Igmp-enable	integer
        VendorSpecificAttribute	4874	24	Unisphere-Pppoe-Description	string
        VendorSpecificAttribute	4874	25	Unisphere-Redirect-VR-Name	string
        VendorSpecificAttribute	4874	26	Unisphere-Qos-Profile-Name	string
        VendorSpecificAttribute	4874	27	Unisphere-Pppoe-Max-Sessions	integer
        VendorSpecificAttribute	4874	28	Unisphere-Pppoe-Url	string
        VendorSpecificAttribute	4874	29	Unisphere-Qos-Profile-Interface-Type	integer
        VendorSpecificAttribute	4874	30	Unisphere-Qos-Nas-Port-Method	integer
        VendorSpecificAttribute	4874	31	Unisphere-Service-Bundle	string
        VendorSpecificAttribute	4874	32	Unisphere-Tunnel-Tos	integer
        VendorSpecificAttribute	4874	33	Unisphere-Tunnel-Maximum-Sessions	integer
        VendorSpecificAttribute	4874	34	Unisphere-Framed-Ip-Route-Tag	string
        VendorSpecificAttribute	4874	35	Unisphere-Tunnel-Dialout-Number	string
        VendorSpecificAttribute	4874	36	Unisphere-Ppp-Username	string
        VendorSpecificAttribute	4874	37	Unisphere-Ppp-Password	string
        VendorSpecificAttribute	4874	38	Unisphere-Ppp-Protocol	integer
        VendorSpecificAttribute	4874	39	Unisphere-Tunnel-Min-Bps	integer
        VendorSpecificAttribute	4874	40	Unisphere-Tunnel-Max-Bps	integer
        VendorSpecificAttribute	4874	41	Unisphere-Tunnel-Bearer-Type	integer
        VendorSpecificAttribute	4874	42	Unisphere-Input-Gigapkts	integer
        VendorSpecificAttribute	4874	43	Unisphere-Ouput-Gigapkts	integer
        VendorSpecificAttribute	4874	44	Unisphere-Tunnel-Interface-Id	string
        VendorSpecificAttribute	4874	45	Unisphere-Ipv6-Virtual-Router	string
        VendorSpecificAttribute	4874	46	Unisphere-Ipv6-Local-Interface	string
        VendorSpecificAttribute	4874	47	Unisphere-Ipv6-Primary-DNS	string
        VendorSpecificAttribute	4874	48	Unisphere-Ipv6-Secondary-DNS	string
        VendorSpecificAttribute	4874	49	Unisphere-Sdx-Service-Name	string
        VendorSpecificAttribute	4874	50	Unisphere-Sdx-Session-Volume-Quota	string
        VendorSpecificAttribute	4874	51	Unisphere-Tunnel-Disconnect-Cause-Info	string
        VendorSpecificAttribute	4874	51	Unisphere-Disconnect-Cause	hexadecimal
        VendorSpecificAttribute	4874	53	Unisphere-Service-Description	string
        VendorSpecificAttribute	4874	55	Unisphere-Dhcp-Options	hexadecimal
        VendorSpecificAttribute	4874	56	Unisphere-Dhcp-Mac-Addr	string
        VendorSpecificAttribute	4874	57	Unisphere-Dhcp-Gi-Address	ipaddr
        VendorSpecificAttribute	4874	58	Unisphere-LI-Action	octet
        VendorSpecificAttribute	4874	59	Unisphere-Med-Dev-Handle	octet
        VendorSpecificAttribute	4874	60	Unisphere-Med-Ip-Address	octet
        VendorSpecificAttribute	4874	61	Unisphere-Med-Port-Number	octet

        # VendorId 5535
        VendorSpecificAttribute	5535	1	3GPP2-Pre-Shared-Secret-Request	integer
        VendorSpecificAttribute	5535	2	3GPP2-Security-Level	integer
        VendorSpecificAttribute	5535	3	3GPP2-Pre-Shared-Secret	octet
        VendorSpecificAttribute	5535	4	3GPP2-Reverse-Tunnel-Specification	integer
        VendorSpecificAttribute	5535	5	3GPP2-Services-Class-Option	integer
        VendorSpecificAttribute	5535	6	3GPP2-Container	octet
        VendorSpecificAttribute	5535	7	3GPP2-Home-Agent-Address	ipaddr
        VendorSpecificAttribute	5535	8	3GPP2-Key-Id	octet
        VendorSpecificAttribute	5535	9	3GPP2-PCF-Address	ipaddr
        VendorSpecificAttribute	5535	10	3GPP2-BSID	string
        VendorSpecificAttribute	5535	11	3GPP2-S-Key	octet
        VendorSpecificAttribute	5535	12	3GPP2-S-Lifetime	integer
        VendorSpecificAttribute	5535	13	3GPP2-S-Request	integer
        VendorSpecificAttribute	5535	16	3GPP2-Service-Option	integer
        VendorSpecificAttribute	5535	17	3GPP2-Forward-Type	integer
        VendorSpecificAttribute	5535	18	3GPP2-Reverse-Type	integer
        VendorSpecificAttribute	5535	19	3GPP2-Frame-Size	integer
        VendorSpecificAttribute	5535	20	3GPP2-Forward-Fundamental-RC	integer
        VendorSpecificAttribute	5535	21	3GPP2-Reverse-Fundamental-RC	integer
        VendorSpecificAttribute	5535	22	3GPP2-IP-Technology	integer
        VendorSpecificAttribute	5535	23	3GPP2-Compulsory-Tunnel	integer
        VendorSpecificAttribute	5535	24	3GPP2-Release-Indicator	integer
        VendorSpecificAttribute	5535	30	3GPP2-Num-Active	integer
        VendorSpecificAttribute	5535	31	3GPP2-SDB-Input-Octets	integer
        VendorSpecificAttribute	5535	32	3GPP2-SDB-Output-Octets	integer
        VendorSpecificAttribute	5535	33	3GPP2-Num-SDB-Input	integer
        VendorSpecificAttribute	5535	34	3GPP2-Num-SDB-Output	integer
        VendorSpecificAttribute	5535	36	3GPP2-IP-QOS	integer
        VendorSpecificAttribute	5535	39	3GPP2-Airlink-QOS	integer
        VendorSpecificAttribute	5535	40	3GPP2-Airlink-Record-Type	integer
        VendorSpecificAttribute	5535	40	3GPP2-Mobile-Indicator	integer
        VendorSpecificAttribute	5535	41	3GPP2-R-P-Session-ID	integer
        VendorSpecificAttribute	5535	42	3GPP2-Airlink-Sequence-Number	integer
        VendorSpecificAttribute	5535	43	3GPP2-Num-Bytes-Received-Total	integer
        VendorSpecificAttribute	5535	44	3GPP2-Correlation-Id	string
        VendorSpecificAttribute	5535	46	3GPP2-Mobile-IP-Signalling-Inbound	integer
        VendorSpecificAttribute	5535	47	3GPP2-Mobile-IP-Signalling-Outbound	integer
        VendorSpecificAttribute	5535	48	3GPP2-Session-Cont	integer
        VendorSpecificAttribute	5535	49	3GPP2-Active-Time	integer
        VendorSpecificAttribute	5535	50	3GPP2-Frame-Format	integer

        # VendorId 5586
        VendorSpecificAttribute	5586	1	IPW-Tier-Of-Service	integer
        VendorSpecificAttribute	5586	2	IPW-Roaming-Indication	integer
        VendorSpecificAttribute	5586	3	IPW-ISP-LNS-Name	string
        VendorSpecificAttribute	5586	4	IPW-User-Trace-Indicator	integer
        VendorSpecificAttribute	5586	5	IPW-User-Name-Type	integer
        VendorSpecificAttribute	5586	6	IPW-L2TP-Tunnel-If-Index	string
        VendorSpecificAttribute	5586	8	IPW-Acct-Terminate-Cause	integer
        VendorSpecificAttribute	5586	9	IPW-ISP-Name	string
        VendorSpecificAttribute	5586	10	IPW-Node-B-Id	string
        VendorSpecificAttribute	5586	11	IPW-IMEI-Status	integer
        VendorSpecificAttribute	5586	12	IPW-SV-Status	integer
        VendorSpecificAttribute	5586	13	IPW-L2TP-Tunnel-Local-Sid	string
        VendorSpecificAttribute	5586	14	IPW-UMTS-Authentication-Vector	string
        VendorSpecificAttribute	5586	15	IPW-UMTS-Resynchronisation-Token	string
        VendorSpecificAttribute	5586	16	IPW-Additional-PDP-Contexts-Allowed	string
        VendorSpecificAttribute	5586	17	IPW-PDP-Context-Accounting	string
        VendorSpecificAttribute	5586	18	IPW-UE-Software-Version	string
        VendorSpecificAttribute	5586	19	IPW-UE-Hardware-Identity	string
        VendorSpecificAttribute	5586	20	IPW-GSM-Authentication-Vector	string
        VendorSpecificAttribute	5586	21	IPW-Serving-INC-IP-Address	ipaddr
        VendorSpecificAttribute	5586	22	IPW-UE-Application-Version	string
        VendorSpecificAttribute	5586	23	IPW-Additional-Context-Config	string
        VendorSpecificAttribute	5586	24	IPW-UEInfo-RSCP	string
        VendorSpecificAttribute	5586	25	IPW-UEInfo-ISCP	string
        VendorSpecificAttribute	5586	26	IPW-UEInfo-RSCP-ISCP-Margin	string

        # VendorId 5624
        VendorSpecificAttribute	5624	1	Command-Code	string

        # VendorId 5948
        VendorSpecificAttribute	5948	1	Issanni-SoftFlow_Template	string
        VendorSpecificAttribute	5948	2	Issanni-NAT_Support	string
        VendorSpecificAttribute	5948	3	Issanni-Routing_Context	string
        VendorSpecificAttribute	5948	4	Issanni-Tunnel_Name	string
        VendorSpecificAttribute	5948	5	Issanni-IP_Pool_Name	string
        VendorSpecificAttribute	5948	6	Issanni-PPPoE_URL	string
        VendorSpecificAttribute	5948	7	Issanni-PPPoE_MOTM	string
        VendorSpecificAttribute	5948	8	Issanni-Service	string
        VendorSpecificAttribute	5948	9	Issanni-Pri_DNS	ipaddr
        VendorSpecificAttribute	5948	10	Issanni-Sec_DNS	ipaddr
        VendorSpecificAttribute	5948	11	Issanni-Pri_NBNS	ipaddr
        VendorSpecificAttribute	5948	12	Issanni-Sec_NBNS	ipaddr
        VendorSpecificAttribute	5948	13	Issanni-Traffic_Class	string
        VendorSpecificAttribute	5948	14	Issanni-Tunnel-Type	integer
        VendorSpecificAttribute	5948	15	Issanni-NAT-Type	integer
        VendorSpecificAttribute	5948	16	Issanni-QOS-Class	string
        VendorSpecificAttribute	5948	17	Issanni-Interface-Name	string

        # VendorId 6618
        VendorSpecificAttribute	6618	1	Quintum-AVPair	string
        VendorSpecificAttribute	6618	2	Quintum-NAS-Port	string
        VendorSpecificAttribute	6618	23	Quintum-h323-remote-address	string
        VendorSpecificAttribute	6618	24	Quintum-h323-conf-id	string
        VendorSpecificAttribute	6618	25	Quintum-h323-setup-time	string
        VendorSpecificAttribute	6618	26	Quintum-h323-call-origin	string
        VendorSpecificAttribute	6618	27	Quintum-h323-call-type	string
        VendorSpecificAttribute	6618	28	Quintum-h323-connect-time	string
        VendorSpecificAttribute	6618	29	Quintum-h323-disconnect-time	string
        VendorSpecificAttribute	6618	30	Quintum-h323-disconnect-cause	string
        VendorSpecificAttribute	6618	31	Quintum-h323-voice-quality	string
        VendorSpecificAttribute	6618	33	Quintum-h323-gw-id	string
        VendorSpecificAttribute	6618	35	Quintum-h323-incoming-conf-id	string
        VendorSpecificAttribute	6618	101	Quintum-h323-credit-amount	string
        VendorSpecificAttribute	6618	102	Quintum-h323-credit-time	string
        VendorSpecificAttribute	6618	103	Quintum-h323-return-code	string
        VendorSpecificAttribute	6618	104	Quintum-h323-prompt-id	string
        VendorSpecificAttribute	6618	105	Quintum-h323-time-and-day	string
        VendorSpecificAttribute	6618	106	Quintum-h323-redirect-number	string
        VendorSpecificAttribute	6618	107	Quintum-h323-preferred-lang	string
        VendorSpecificAttribute	6618	108	Quintum-h323-redirect-ip-address	string
        VendorSpecificAttribute	6618	109	Quintum-h323-billing-model	string
        VendorSpecificAttribute	6618	110	Quintum-h323-currency-type	string

        # VendorId 7000
        VendorSpecificAttribute	7000	1	Slipstream-Auth	string

        # VendorId 8226
        VendorSpecificAttribute	8226	102	Giganews-aucl	integer
        VendorSpecificAttribute	8226	103	Giganews-connratelimit	integer
        VendorSpecificAttribute	8226	104	Giganews-gbpm	integer

        # VendorId 8741
        VendorSpecificAttribute	8741	1	SonicWall-User-Privilege	integer
        VendorSpecificAttribute	8741	2	SonicWall-User-Privileges	string
        VendorSpecificAttribute	8741	3	SonicWall-User-Group	string
        VendorSpecificAttribute	8741	4	SonicWall-User-Groups	string

        # VendorId 8744
        VendorSpecificAttribute	8744	0	Colubris-AVPAIR	string

        # VendorId 9048
        VendorSpecificAttribute	9048	0	OSC-AVPAIR	string
        VendorSpecificAttribute	9048	1	OSC-Uid	integer
        VendorSpecificAttribute	9048	2	OSC-Gid	integer
        VendorSpecificAttribute	9048	3	OSC-Home	string
        VendorSpecificAttribute	9048	4	OSC-Shell	string
        VendorSpecificAttribute	9048	5	OSC-Integrity-Message	octet

        # VendorId 9148
        VendorSpecificAttribute	9148	1	Acme-FlowID	string
        VendorSpecificAttribute	9148	2	Acme-FlowType	string
        VendorSpecificAttribute	9148	10	Acme-Flow-In-Realm	string
        VendorSpecificAttribute	9148	11	Acme-Flow-In-Src-Addr	ipaddr
        VendorSpecificAttribute	9148	12	Acme-Flow-In-Src-Port	integer
        VendorSpecificAttribute	9148	13	Acme-Flow-In-Dst-Addr	ipaddr
        VendorSpecificAttribute	9148	14	Acme-Flow-In-Dst-Port	integer
        VendorSpecificAttribute	9148	20	Acme-Flow-Out-Realm	string
        VendorSpecificAttribute	9148	21	Acme-Flow-Out-Src-Addr	ipaddr
        VendorSpecificAttribute	9148	22	Acme-Flow-Out-Src-Port	integer
        VendorSpecificAttribute	9148	23	Acme-Flow-Out-Dst-Addr	ipaddr
        VendorSpecificAttribute	9148	24	Acme-Flow-Out-Dst-Port	integer

        # VendorId 10055
        VendorSpecificAttribute	10055	1	RP-Upstream-Speed-Limit	integer
        VendorSpecificAttribute	10055	2	RP-Downstream-Speed-Limit	integer

        # VendorId 10415
        VendorSpecificAttribute	10415	1	3GPP-IMSI	string
        VendorSpecificAttribute	10415	2	3GPP-Charging-Id	integer
        VendorSpecificAttribute	10415	3	3GPP-PDP-Type	integer
        VendorSpecificAttribute	10415	4	3GPP-CG-Address	ipaddr
        VendorSpecificAttribute	10415	5	3GPP-GPRS-QoS-Profile	string
        VendorSpecificAttribute	10415	6	3GPP-SGSN-Address	ipaddr
        VendorSpecificAttribute	10415	7	3GPP-GGSN-Address	ipaddr
        VendorSpecificAttribute	10415	8	3GPP-IMSI-MCC-MNC	string
        VendorSpecificAttribute	10415	9	3GPP-GGSN-MCC-MNC	string
        VendorSpecificAttribute	10415	10	3GPP-NSAPI	string
        VendorSpecificAttribute	10415	11	3GPP-Session-Stop-Indicator	string
        VendorSpecificAttribute	10415	12	3GPP-Selection-Mode	string
        VendorSpecificAttribute	10415	13	3GPP-Charging-Characteristics	string
        VendorSpecificAttribute	10415	14	3GPP-CG-IPv6-address	string
        VendorSpecificAttribute	10415	15	3GPP-SGSN-IPv6-Address	string
        VendorSpecificAttribute	10415	16	3GPP-GGSN-IPv6-Address	string
        VendorSpecificAttribute	10415	17	3GPP-IPv6-DNS-Servers	string
        VendorSpecificAttribute	10415	18	3GPP-SGSN-MCC-MNC	string
        VendorSpecificAttribute	10415	20	3GPP-IMEISV	string
        VendorSpecificAttribute	10415	21	3GPP-RAT-Type	octet
        VendorSpecificAttribute	10415	22	3GPP-User-Location-Info	octet
        VendorSpecificAttribute	10415	23	3GPP-MS-Time-Zone	octet
        VendorSpecificAttribute	10415	26	3GPP-Negotiated-DSCP	octet

        # VendorId 12902
        VendorSpecificAttribute	12902	1	User-Group-Name	string
        VendorSpecificAttribute	12902	2	Client-BW-Info	string

        # VendorId 13209
        VendorSpecificAttribute	13209	1	Ipass-13209-1	string
        VendorSpecificAttribute	13209	9	Ipass-13209-9	string
        VendorSpecificAttribute	13209	21	Ipass-13209-21	string
        VendorSpecificAttribute	13209	24	Ipass-13209-24	string
        VendorSpecificAttribute	13209	42	Ipass-13209-42	string
        VendorSpecificAttribute	13209	49	Ipass-13209-49	string
        VendorSpecificAttribute	13209	51	Ipass-13209-51	string
        VendorSpecificAttribute	13209	52	Ipass-13209-52	string

        # VendorId 14122
        VendorSpecificAttribute	14122	1	WISPr-Location-ID	string
        VendorSpecificAttribute	14122	2	WISPr-Location-Name	string
        VendorSpecificAttribute	14122	3	WISPr-Logoff-URL	string
        VendorSpecificAttribute	14122	4	WISPr-Redirection-URL	string
        VendorSpecificAttribute	14122	5	WISPr-Bandwidth-Min-Up	integer
        VendorSpecificAttribute	14122	6	WISPr-Bandwidth-Min-Down	integer
        VendorSpecificAttribute	14122	7	WISPr-Bandwidth-Max-Up	integer
        VendorSpecificAttribute	14122	8	WISPr-Bandwidth-Max-Down	integer
        VendorSpecificAttribute	14122	9	WISPr-Session-Terminate-Time	string
        VendorSpecificAttribute	14122	10	WISPr-Session-Terminate-End-Of-Day	string
        VendorSpecificAttribute	14122	11	WISPr-Billing-Class-Of-Service	string

        # VendorId 14179
        VendorSpecificAttribute	14179	1	Airespace-WLAN-Id	integer
        VendorSpecificAttribute	14179	2	Airespace-QoS-Level	integer
        VendorSpecificAttribute	14179	3	Airespace-DSCP	integer
        VendorSpecificAttribute	14179	4	Airespace-802.1p-Tag	integer
        VendorSpecificAttribute	14179	5	Airespace-Interface-Name	string
        VendorSpecificAttribute	14179	6	Airespace-ACL-Name	string

        # VendorId 14413
        VendorSpecificAttribute	14413	1	WeRoam-phase2Realm	string
        VendorSpecificAttribute	14413	2	WeRoam-Location-Id	string
        VendorSpecificAttribute	14413	3	WeRoam-Location-Name	string
        VendorSpecificAttribute	14413	4	WeRoam-Indicator	string
        VendorSpecificAttribute	14413	5	WeRoam-Service	integer
        VendorSpecificAttribute	14413	6	WeRoam-WISP-Id	string
        VendorSpecificAttribute	14413	7	WeRoam-Unique-Location-Id	integer
        VendorSpecificAttribute	14413	8	WeRoam-Country-Code	string
        VendorSpecificAttribute	14413	9	WeRoam-Location-UTC-Offset	integer
        VendorSpecificAttribute	14413	10	WeRoam-Location-DST-Flag	integer
        VendorSpecificAttribute	14413	11	WeRoam-Location-EOD	integer
        VendorSpecificAttribute	14413	12	WeRoam-Location-Type	integer
        VendorSpecificAttribute	14413	13	WeRoam-Billing-Category	integer
        VendorSpecificAttribute	14413	14	WeRoam-WISP-Name	string

        # VendorId 14525
        VendorSpecificAttribute	14525	1	TRPZ-VLAN-Name	string
        VendorSpecificAttribute	14525	2	TRPZ-Mobility-Profile	string
        VendorSpecificAttribute	14525	3	TRPZ-Encryption-Type	string
        VendorSpecificAttribute	14525	4	TRPZ-Time-Of-Day	string

        # VendorId 14895
        VendorSpecificAttribute	14895	1	Propel-Accelerate	integer
        VendorSpecificAttribute	14895	2	Propel-Dialed-Digits	string
        VendorSpecificAttribute	14895	3	Propel-Client-IP-Address	ipaddr
        VendorSpecificAttribute	14895	4	Propel-Client-NAS-IP-Address	ipaddr
        VendorSpecificAttribute	14895	5	Propel-Client-Source-ID	integer
        VendorSpecificAttribute	14895	6	Propel-Content-Filter	integer

        # VendorId 14988
        VendorSpecificAttribute	14988	1	Mikrotik-Recv-Limit	integer
        VendorSpecificAttribute	14988	2	Mikrotik-Xmit-Limit	integer
        VendorSpecificAttribute	14988	3	Mikrotik-Group	string
        VendorSpecificAttribute	14988	4	Mikrotik-Wireless-Forward	integer
        VendorSpecificAttribute	14988	5	Mikrotik-Wireless-Skip-Dot1x	integer
        VendorSpecificAttribute	14988	6	Mikrotik-Wireless-Enc-Algo	integer
        VendorSpecificAttribute	14988	7	Mikrotik-Wireless-Enc-Key	string
        VendorSpecificAttribute	14988	8	Mikrotik-Rate-Limit	string
        VendorSpecificAttribute	14988	9	Mikrotik-Realm	string

        # VendorId 16313
        VendorSpecificAttribute	16313	1	VNC-PPPoE-CBQ-RX	integer
        VendorSpecificAttribute	16313	2	VNC-PPPoE-CBQ-TX	integer
        VendorSpecificAttribute	16313	3	VNC-PPPoE-CBQ-RX-Fallback	integer
        VendorSpecificAttribute	16313	4	VNC-PPPoE-CBQ-TX-Fallback	integer

        # VendorId 17458
        VendorSpecificAttribute	17458	0	CCA-AVPAIR	string
        VendorSpecificAttribute	17458	1	CCA-Service-Identifier	string

        """;
}