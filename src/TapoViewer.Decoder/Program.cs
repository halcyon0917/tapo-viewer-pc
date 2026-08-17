namespace TapoViewer.Decoder;

/// <summary>
/// The sandboxed decoder process.
/// </summary>
/// <remarks>
/// Runs at low integrity inside a Job Object, launched by the UI. It receives the stream target
/// and credentials over inherited stdin — never on the command line, which is world-readable via
/// the process list — and reports its window handle and playback state back over stdout.
/// </remarks>
internal static class Program
{
    private static int Main(string[] args)
    {
        if (Array.IndexOf(args, "--selftest") >= 0)
        {
            try
            {
                return SelfTest.Run(args);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Self-test failed: {ex.GetType().Name}: {ex.Message}");
                return 1;
            }
        }

        if (Array.IndexOf(args, "--host") >= 0)
        {
            using var host = new DecoderHost(Console.Out);
            try
            {
                return host.Run(args);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Decoder host failed: {ex.GetType().Name}: {ex.Message}");
                return 1;
            }
        }

        Console.Error.WriteLine(
            "This process is launched by TapoViewer.App and is not meant to be run directly.\n" +
            "For diagnostics: TapoViewer.Decoder --selftest [--quality high|standard] [--seconds N]");

        return 64;
    }
}
