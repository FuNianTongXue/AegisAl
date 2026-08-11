using System.Diagnostics;

public static class DiagnosticsRunner
{
    public static void RunStatus()
    {
        Process.Start("/usr/bin/uptime");
    }
}
