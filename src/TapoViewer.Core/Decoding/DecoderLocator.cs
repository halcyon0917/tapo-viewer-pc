namespace TapoViewer.Core.Decoding;

/// <summary>Finds the decoder executable in both deployed and development layouts.</summary>
public static class DecoderLocator
{
    public const string ExecutableName = "TapoViewer.Decoder.exe";

    /// <summary>
    /// A candidate only counts if its managed assembly sits beside it.
    /// </summary>
    /// <remarks>
    /// MSBuild copies the decoder's apphost <c>.exe</c> into a referencing project's output even
    /// with <c>ReferenceOutputAssembly=false</c>, without the <c>.dll</c> it needs to run. Such an
    /// orphan launches and immediately dies with "The application to execute does not exist",
    /// which looks exactly like a sandbox failure. Checking for the companion assembly is what
    /// distinguishes a real deployment from that decoy.
    /// </remarks>
    private static bool IsCompleteDeployment(string executablePath)
        => File.Exists(executablePath)
           && File.Exists(Path.ChangeExtension(executablePath, ".dll"));

    /// <summary>Returns the decoder path, or <see langword="null"/> if it cannot be found.</summary>
    public static string? Locate(string? explicitPath = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            return IsCompleteDeployment(explicitPath) ? explicitPath : null;
        }

        // Deployed: the decoder gets its own subdirectory so its libVLC payload cannot collide
        // with the host application's files.
        var nested = Path.Combine(AppContext.BaseDirectory, "decoder", ExecutableName);
        if (IsCompleteDeployment(nested))
        {
            return nested;
        }

        // Flat deployment next to the host application.
        var sibling = Path.Combine(AppContext.BaseDirectory, ExecutableName);
        if (IsCompleteDeployment(sibling))
        {
            return sibling;
        }

        // Development: walk up to the repository root, then into the decoder's build output.
        foreach (var configuration in (string[])["Debug", "Release"])
        {
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            while (directory is not null)
            {
                var candidate = Path.Combine(
                    directory.FullName,
                    "src",
                    "TapoViewer.Decoder",
                    "bin",
                    configuration,
                    "net8.0-windows",
                    ExecutableName);

                if (IsCompleteDeployment(candidate))
                {
                    return candidate;
                }

                directory = directory.Parent;
            }
        }

        return null;
    }

    public static string LocateOrThrow(string? explicitPath = null)
        => Locate(explicitPath)
           ?? throw new FileNotFoundException(
               $"Could not find {ExecutableName}. Build the TapoViewer.Decoder project.");
}
