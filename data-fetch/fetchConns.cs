using ip_check.data_fetch;
using System;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
public class AbuseIpData
{
    public required string IpAddress { get; set; }
    public bool IsPublic { get; set; }
    public int IpVersion { get; set; }
    public bool IsWhitelisted { get; set; }
    public int AbuseConfidenceScore { get; set; }
    public required string CountryCode { get; set; }
    public string? UsageType { get; set; }
    public string? Isp { get; set; }
    public string? Domain { get; set; }
    public List<string>? Hostnames { get; set; }
    public bool IsTor { get; set; }
    public int TotalReports { get; set; }
    public int NumDistinctUsers { get; set; }
    public string? LastReportedAt { get; set; } // or DateTime? if you expect real dates
}

public class AbuseIpResponse
{
    public AbuseIpData? Data { get; set; }
}

public class TcpConnection
{
    public required string LocalAddress { get; set; }
    public ushort LocalPort { get; set; }
    public required string RemoteAddress { get; set; }
    public ushort RemotePort { get; set; }
    public required string State { get; set; }
    public int ProcessId { get; set; }
    public required string ProcessPath { get; set; }
    public bool isMalicious { get; set; }
}


namespace ip_check.data_fetch
{
    public class FetchConns
    {
        DataTable _dataTable;

        public const int AF_INET = 2;

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            public MIB_TCPROW_OWNER_PID table;
        }

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable,
            ref int dwOutBufLen,
            bool sort,
            int ipVersion,
            TCP_TABLE_CLASS tblClass,
            uint reserved);

        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private Dictionary<string, TcpConnection> _connections = new Dictionary<string, TcpConnection>();

        HttpClient _httpClient = new HttpClient();

        private ushort Ntoh(uint netshort)
        {
            return (ushort)(((netshort & 0xFF) << 8) | ((netshort & 0xFF00) >> 8));
        }

        private Dictionary<string, TcpConnection> GetTcpConnections()
        {
            IntPtr tcpTablePtr = IntPtr.Zero;
            int dwOutBufLen = 0;
            bool sort = true;
            int ipVersion = AF_INET;
            TCP_TABLE_CLASS tblClass = TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_CONNECTIONS;
            uint reserved = 0;


            uint stat = GetExtendedTcpTable(tcpTablePtr, ref dwOutBufLen, sort, ipVersion, tblClass, reserved);

            tcpTablePtr = Marshal.AllocHGlobal(dwOutBufLen);

            Console.WriteLine("size_of_table " + dwOutBufLen);

            uint result = GetExtendedTcpTable(tcpTablePtr, ref dwOutBufLen, sort, ipVersion, tblClass, reserved);

            if (result != 0)
            {
                Console.WriteLine("Error retrieving TCP connections: " + result);
                return _connections;
            }

            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            int numEntries = Marshal.ReadInt32(tcpTablePtr);
            IntPtr currentRowPtr = IntPtr.Add(tcpTablePtr, sizeof(int));



            for (int i = 0; i < numEntries; i++, currentRowPtr = IntPtr.Add(currentRowPtr, rowSize))
            {
                MIB_TCPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(currentRowPtr);
                TcpConnection conn = new TcpConnection
                {
                    LocalAddress = new System.Net.IPAddress(BitConverter.GetBytes(row.localAddr)).ToString(),
                    LocalPort = Ntoh(row.localPort),
                    RemoteAddress = new System.Net.IPAddress(BitConverter.GetBytes(row.remoteAddr)).ToString(),
                    RemotePort = Ntoh(row.remotePort),
                    State = row.state.ToString(),
                    ProcessId = (int)row.owningPid,
                    ProcessPath = Process.GetProcessById((int)row.owningPid).ProcessName
                };
                _connections[$"{conn.LocalAddress}:{conn.LocalPort}"] = conn; // keep this as the local because you could have multiple connections to the same remote address and port

            }

            return _connections;
        }

        private async Task VerifyIPAddress(TcpConnection conn)
        {
            string RemoteIP = conn.RemoteAddress;
            Console.WriteLine($"Verifying IP Address: {RemoteIP}");
            await Task.Delay(1000);

            var response = await _httpClient.GetAsync($"https://api.abuseipdb.com/api/v2/check?ipAddress={RemoteIP}");

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadFromJsonAsync<AbuseIpResponse>(); // don't need to do try here because i use AggregateException for the WaitAll later

                Console.WriteLine("Data was null, something went wrong with the API call.");
                for (int i = 0; i < 4; ++i)
                {
                    if (content?.Data == null)
                    {
                        Console.WriteLine($"retrying request for {RemoteIP}, previous call failed...");
                        response = await _httpClient.GetAsync($"https://api.abuseipdb.com/api/v2/check?ipAddress={RemoteIP}");

                        content = await response.Content.ReadFromJsonAsync<AbuseIpResponse>();

                        await Task.Delay(1000);
                    }
                }

                if (content?.Data == null)
                {
                    throw new Exception("Bad Response");
                }


                if (content.Data.AbuseConfidenceScore >= 80)
                {
                    _connections[$"{conn.LocalAddress}:{conn.LocalPort}"].isMalicious = true;
                }
            }
        }

        private void VerifyAllIPAddresses()
        {
            HashSet<string> seenIPs = new HashSet<string>();
            List<Task> IPVerifications = [];

            foreach (var conn in _connections.Values)
            {
                if (seenIPs.Contains(conn.RemoteAddress))
                {
                    Console.WriteLine($"IP Address {conn.RemoteAddress} has already been seen. Skipping verification.");
                    continue;


                }
                Task t = VerifyIPAddress(conn);
                IPVerifications.Add(t);
                seenIPs.Add(conn.RemoteAddress);
            }

            try
            {
                Task.WaitAll(IPVerifications);
            }
            catch (AggregateException aggEx)
            {
                foreach (var ex in aggEx.InnerExceptions)
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }


        public void PrintTcpConnections()
        {
            foreach (var conn in _connections.Values)
            {
                Console.WriteLine($"Local: {conn.LocalAddress}:{conn.LocalPort}, Remote: {conn.RemoteAddress}:{conn.RemotePort}, State: {conn.State}, PID: {conn.ProcessId}");
            }
        }

        public async Task<DataTable> PopulateDataTableTCP() {
            return await Task.Run(() => {
                System.Diagnostics.Debug.WriteLine("STARTING ");
                _connections = GetTcpConnections();
                VerifyAllIPAddresses();
                _dataTable.Clear();
                foreach (var conn in _connections.Values)
                {
                    System.Diagnostics.Debug.WriteLine("IN LOOP");
                    _dataTable.Rows.Add(conn.RemoteAddress, "TCP", conn.ProcessId, conn.ProcessPath, conn.isMalicious);
                }
                return _dataTable;
            });
        }

        public FetchConns()
        {
            _dataTable = new DataTable();
            _dataTable.Columns.Add("IP", typeof(string));
            _dataTable.Columns.Add("ConnType", typeof(string));
            _dataTable.Columns.Add("Process", typeof(int));
            _dataTable.Columns.Add("ProcLocation", typeof(string));
            _dataTable.Columns.Add("Malicious", typeof(bool));
            _httpClient.DefaultRequestHeaders.Add("Key", System.Environment.GetEnvironmentVariable("ABUSEIPDB_KEY")); // MYKEY SHOULD BE PASSED BY THE USER INTO THE PROGRAM AND THEY CAN CHOOSE IT TO BE SAVED TO CONFIGURATION FOR SUBSEQUENT APPLICATION BOOTS
        }

    }

}


// See https://aka.ms/new-console-template for more information


// WHEN VERIFYING THE IP ADDRESSES YOUCAN PUT CHECKED IP ADDRESSES IN A MEMO TO ENSURE SEEN IP ADDRESSES ARE NOT PROCESSED IN THE API CALLS TO VirusTotal/ABUSEIPDB. That way, you never exceed the daily count
// PERHAPS USE ABUSEIPDB FOR IP ADDRESS CHECKING BECAUSE IT DOESN'T HAVE A BY THE MINUTE RATE LIMIT LIKE VIRUSTOTAL DOES.