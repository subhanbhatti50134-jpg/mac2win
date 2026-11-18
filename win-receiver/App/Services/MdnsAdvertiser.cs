using System.Runtime.InteropServices;

namespace Mac2WinReceiver.App.Services;

/// <summary>Windows DNS-SD (dnsapi.dll) service advertisement.</summary>
/// <remarks>
/// Signatures per Microsoft Learn (no local Windows Kits headers — layouts fetched at
/// design time from learn.microsoft.com). Registers <c>_mac2win._tcp.local</c> so the Mac's
/// NWBrowser can discover the receiver (SPEC §1.1 / ADR-006).
/// </remarks>
public sealed class MdnsAdvertiser : IDisposable
{
    private const string Dnsapi = "dnsapi.dll";
    private const uint DnsQueryRequestVersion1 = 1;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate void RegisterCompleteCallback(
        IntPtr pRegisterRequest, IntPtr pContext, uint dwStatus);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DnsServiceRegisterRequest
    {
        public uint Version;
        public uint InterfaceIndex;
        public IntPtr pServiceInstance;
        public IntPtr pCallback;
        public IntPtr pContext;
        public IntPtr hCredentials;
        public int UnicastEnabled;
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

    [DllImport(Dnsapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint DnsServiceRegister(
        ref DnsServiceRegisterRequest pRegisterRequest, out IntPtr pCancel);

    [DllImport(Dnsapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint DnsServiceDeRegister(ref IntPtr pCancel);

    [DllImport(Dnsapi, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint DnsServiceFreeInstance(IntPtr pServiceInstance);

    private const uint DnsRequestPending = 0x0000048B; // ERROR_IO_PENDING

    private readonly int _port;
    private readonly string _instanceName;
    private IntPtr _cancelHandle;
    private bool _registered;
    private readonly List<object> _roots = new(); // root delegates + pinned strings

    public MdnsAdvertiser(int port, string deviceName)
    {
        _port = port;
        _instanceName = $"{deviceName}._mac2win._tcp.local";
    }

    public void Start()
    {
        if (_registered) return;

        var txtKeys = new[] { "pv", "ver" };
        var txtValues = new[] { "1", "1" };

        var keyPtrs = txtKeys.Select(s => Marshal.StringToCoTaskMemUni(s)).ToArray();
        var valuePtrs = txtValues.Select(s => Marshal.StringToCoTaskMemUni(s)).ToArray();
        var keysArr = Marshal.AllocCoTaskMem(keyPtrs.Length * IntPtr.Size);
        var valuesArr = Marshal.AllocCoTaskMem(valuePtrs.Length * IntPtr.Size);
        for (var i = 0; i < keyPtrs.Length; i++)
        {
            Marshal.WriteIntPtr(keysArr, i * IntPtr.Size, keyPtrs[i]);
            Marshal.WriteIntPtr(valuesArr, i * IntPtr.Size, valuePtrs[i]);
        }

        var instance = new DnsServiceInstance
        {
            pInstanceName = Marshal.StringToCoTaskMemUni(_instanceName),
            pHostName = IntPtr.Zero,
            pIp4IpAddress = IntPtr.Zero,
            pIp6IpAddress = IntPtr.Zero,
            wPort = (ushort)_port,
            wPriority = 0,
            wWeight = 0,
            dwPropertyCount = (uint)txtKeys.Length,
            ppPropertyKeys = keysArr,
            ppPropertyValues = valuesArr,
            dwInterfaceIndex = 0,
        };

        var instPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<DnsServiceInstance>());
        Marshal.StructureToPtr(instance, instPtr, fDeleteOld: false);

        var callback = new RegisterCompleteCallback((_, _, _) => { });
        _roots.Add(callback); // keep delegate rooted for the registration lifetime

        var request = new DnsServiceRegisterRequest
        {
            Version = DnsQueryRequestVersion1,
            InterfaceIndex = 0,
            pServiceInstance = instPtr,
            pCallback = Marshal.GetFunctionPointerForDelegate(callback),
            pContext = IntPtr.Zero,
            hCredentials = IntPtr.Zero,
            UnicastEnabled = 0,
        };

        var status = DnsServiceRegister(ref request, out var cancel);
        if (status != DnsRequestPending && status != 0)
        {
            Marshal.FreeCoTaskMem(instPtr);
            Marshal.FreeCoTaskMem(keysArr);
            Marshal.FreeCoTaskMem(valuesArr);
            foreach (var p in keyPtrs.Concat(valuePtrs)) Marshal.FreeCoTaskMem(p);
            throw new InvalidOperationException($"DnsServiceRegister failed: 0x{status:X8}");
        }

        _cancelHandle = cancel;
        _registered = true;
        // Note: instance memory is owned by DNS-SD after registration; free on deregister.
    }

    public void Stop()
    {
        if (!_registered) return;
        try { DnsServiceDeRegister(ref _cancelHandle); }
        catch { /* best effort */ }
        _registered = false;
        _roots.Clear();
    }

    public void Dispose() => Stop();
}
