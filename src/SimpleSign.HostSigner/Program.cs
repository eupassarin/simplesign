namespace SimpleSign.HostSigner;

internal static class Program
{
    [STAThread]
    public static void Main()
    {
        using var mutex = new Mutex(true, @"Global\SimpleSign.HostSigner", out bool created);
        if (!created)
        {
            return;
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new TrayContext());
    }
}
