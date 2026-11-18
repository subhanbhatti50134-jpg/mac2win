namespace Mac2WinReceiver.Core.Server;

/// <summary>Entry in the receiver's trusted-devices list (SPEC §4, ADR-016).</summary>
public sealed record TrustedDevice(string DeviceId, string DeviceName, DateTimeOffset PairedAt);
