namespace Mac2WinReceiver.App.Services;

/// <summary>Checks the active Windows network profile via HNetCfg.FwPolicy2 COM.
/// SPEC §5: warn when the profile is Public; never bind to Public by default.</summary>
public sealed class NetworkProfileChecker
{
    /// <summary>True when the machine appears to be on a Public network profile.</summary>
    public bool IsPublicProfile()
    {
        try
        {
            var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true);
            if (type is null) return false;
            dynamic fwPolicy2 = Activator.CreateInstance(type)!;
            var profiles = fwPolicy2.CurrentProfileTypes;
            return (profiles & 16) != 0;
        }
        catch
        {
            return false;
        }
    }
}
