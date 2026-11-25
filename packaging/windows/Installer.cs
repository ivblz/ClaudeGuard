using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;
using System.Windows.Forms;

[assembly: AssemblyTitle("ClaudeGuard Installer")]
[assembly: AssemblyProduct("ClaudeGuard")]

internal static class Installer
{
    private static int Run(string file, string args, string directory)
    {
        var start = new ProcessStartInfo(file, args) {
            WorkingDirectory = directory, UseShellExecute = false, CreateNoWindow = true
        };
        using (var process = Process.Start(start)) {
            process.WaitForExit();
            return process.ExitCode;
        }
    }

    [STAThread]
    private static int Main(string[] args)
    {
        bool smoke = args.Length == 1 && args[0] == "--smoke-test";
        try {
            using (var identity = WindowsIdentity.GetCurrent()) {
                string sid = identity.User.Value;
                bool elevatedCopy = args.Length == 2 && args[0] == "--install" && args[1] == sid;
                if (args.Length != 0 && !smoke && !elevatedCopy)
                    throw new InvalidOperationException("Run setup from the administrator account that will use ClaudeGuard.");
                if (!smoke && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)) {
                    var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--install " + sid) {
                        Verb = "runas", UseShellExecute = true
                    };
                    using (var child = Process.Start(start)) {
                        child.WaitForExit();
                        return child.ExitCode;
                    }
                }
            }

            string parent = smoke ? Path.GetTempPath() : Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var stage = Directory.CreateDirectory(Path.Combine(parent, "ClaudeGuard-setup-" + Guid.NewGuid().ToString("N")));
            try {
                using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
                using (var archive = new ZipArchive(stream, ZipArchiveMode.Read)) {
                    archive.ExtractToDirectory(stage.FullName);
                }
                string app = Path.Combine(stage.FullName, "ClaudeGuard");
                if (smoke)
                    return Run(Path.Combine(app, "ClaudeGuard.exe"), "--smoke-test", app);
                string shell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
                return Run(shell, "-NoProfile -ExecutionPolicy Bypass -File \"" + Path.Combine(app, "Setup.ps1") + "\" -ShowErrors", app);
            } finally {
                stage.Delete(true);
            }
        } catch (Exception error) {
            if (!smoke) MessageBox.Show(error.Message, "ClaudeGuard Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
