using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Mac2WinReceiver.App.Services;

/// <summary>Windows DNS-SD (dnsapi.dll) service browser for <c>_mac2win._tcp.local</c>.</summary>
public sealed class MdnsBrowser : IDisposable
{
    private const string Dnsapi = "dnsapi.dll";
    private const uint DnsQueryRequestVersion1 = 1;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void BrowseCallback(
        IntPtr pBrowseRequest, IntPtr pContext, IntPtr pInstance, uint dwFlags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DnsServiceBrowseRequest
    {
        public uint Version;
        public uint InterfaceIndex;
        public IntPtr pQueryName;
        public IntPtr pCallback;
        public IntPtr pContext;
        public IntPtr hReserved;
    }

    [DllImport(Dnsapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint DnsServiceBrowse(
        ref DnsServiceBrowseRequest pBrowseRequest, out IntPtr pCancel);

    [DllImport(Dnsapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint DnsServiceDeRegister(ref IntPtr pCancel);

    private const uint DnsRequestPending = 0x0000048B;
    private const int DnsBrowseFlagAdd = 0x00000001;

    private readonly string _queryName = "_mac2win._tcp.local";
    private IntPtr _cancelHandle;
    private bool _browsing;
    private readonly List<object> _roots = new();

    public event Action<string, string, int>? ServiceFound;

    public void Start()
    {
        if (_browsing) return;
        var callback = new BrowseCallback(OnBrowseCallback);
        _roots.Add(callback);

        var queryName = Marshal.StringToCoTaskMemUni(_queryName);
        var request = new DnsServiceBrowseRequest
        {
            Version = DnsQueryRequestVersion1,
            InterfaceIndex = 0,
            pQueryName = queryName,
            pCallback = Marshal.GetFunctionPointerForDelegate(callback),
            pContext = IntPtr.Zero,
            hReserved = IntPtr.Zero,
        };

        var status = DnsServiceBrowse(ref request, out var cancel);
        if (status != DnsRequestPending && status != 0)
        {
            Marshal.FreeCoTaskMem(queryName);
            throw new InvalidOperationException($"DnsServiceBrowse failed: 0x{status:X8}");
        }

        _cancelHandle = cancel;
        _browsing = true;
    }

    private void OnBrowseCallback(IntPtr pRequest, IntPtr pContext, IntPtr pInstance, uint dwFlags)
    {
        if ((dwFlags & DnsBrowseFlagAdd) == 0) return;
        if (pInstance == IntPtr.Zero) return;

        var inst = Marshal.PtrToStructure<DnsServiceInstance>(pInstance);
        var instanceName = Marshal.PtrToStringUni(inst.pInstanceName) ?? string.Empty;
        var hostName = Marshal.PtrToStringUni(inst.pHostName) ?? string.Empty;
        ServiceFound?.Invoke(instanceName, hostName, inst.wPort);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DnsServiceInstance
    {
        public IntPtr pInstanceName;
        public IntPtr pHostName;
        public IntPtr pIp4IpAddress;
        public IntPtr pIp6IpAddress;
        public ushort wPort;
        public ushort wPriority;
        public ushort wWeight;
        public uint dwPropertyCount;
        public IntPtr ppPropertyKeys;
        public IntPtr ppPropertyValues;
        public uint dwInterfaceIndex;
    }

    public void Stop()
    {
        if (!_browsing) return;
        try { DnsServiceDeRegister(ref _cancelHandle); }
        catch { /* best effort */ }
        _browsing = false;
        _roots.Clear();
    }

    public void Dispose() => Stop();
}
