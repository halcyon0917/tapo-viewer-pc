using System.Windows;
using TapoViewer.App.Dialogs;
using TapoViewer.Core.Configuration;

namespace TapoViewer.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        if (Array.IndexOf(e.Args, "--verify-ui") >= 0)
        {
            Environment.ExitCode = VerifyUi();
            Shutdown(Environment.ExitCode);
        }
    }

    /// <summary>
    /// Constructs every window headlessly and reports whether they load.
    /// </summary>
    /// <remarks>
    /// XAML resource lookups (<c>StaticResource</c>, <c>FindResource</c>) resolve at load time,
    /// not compile time, so a renamed brush or a missing style compiles perfectly and then throws
    /// the first time a user opens the dialog. This makes that failure reachable from a command
    /// line instead of only from a click.
    /// </remarks>
    private static int VerifyUi()
    {
        var sample = new CameraProfile
        {
            Id = "verify-ui",
            DisplayName = "Sample",
            Host = "192.168.1.50",
        };

        try
        {
            _ = new CameraEditorWindow();
            Console.WriteLine("CameraEditorWindow (add mode)  : OK");

            _ = new CameraEditorWindow(sample);
            Console.WriteLine("CameraEditorWindow (edit mode) : OK");

            _ = new MainWindow();
            Console.WriteLine("MainWindow                     : OK");

            // CameraTile must be constructed explicitly. It only appears inside MainWindow's
            // ItemsControl DataTemplate, which is deferred content: with no layout pass and an
            // empty Cameras collection it is never instantiated, so its BAML — and the largest
            // concentration of StaticResource lookups in the app — went unparsed. Two palette
            // keys, Danger and PtzButton, are referenced nowhere else, so renaming either would
            // have left this check printing a green verdict while the app crashed on the first
            // camera tile.
            _ = new Controls.CameraTile();
            Console.WriteLine("CameraTile (user control)      : OK");

            Console.WriteLine("VERDICT: all views load");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"FAILED: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }
}
