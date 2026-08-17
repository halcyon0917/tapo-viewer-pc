using System.Runtime.InteropServices;

namespace TapoViewer.Core.Security;

/// <summary>
/// A short-lived password holder.
/// </summary>
/// <remarks>
/// Deliberately not <c>string</c>. A .NET string is immutable and garbage collected, so a
/// password read into one cannot be erased and may sit in the heap — and therefore in a crash
/// dump or a page file — long after use. This type keeps the characters in a <b>pinned</b>
/// array (so the GC never leaves relocated copies behind) and zeroes them on disposal.
///
/// Also deliberately not <c>SecureString</c>, which Microsoft advises against for new code:
/// it offers no real protection on non-Windows platforms and still has to be marshalled to
/// plaintext to be used, while adding API friction.
///
/// This narrows the window; it does not eliminate it. An attacker who can already read this
/// process's memory while a stream is playing has won regardless. The goal is that a password
/// does not *persist* anywhere it was not explicitly written.
/// </remarks>
public sealed class Secret : IDisposable
{
    private readonly char[] _value;
    private GCHandle _pin;
    private bool _disposed;

    private Secret(int length)
    {
        _value = new char[length];
        // Pin before anything is written, so the only copy ever created lives at a fixed address.
        _pin = GCHandle.Alloc(_value, GCHandleType.Pinned);
    }

    public static Secret FromChars(ReadOnlySpan<char> value)
    {
        var secret = new Secret(value.Length);
        value.CopyTo(secret._value);
        return secret;
    }

    /// <summary>
    /// Converts a <see cref="System.Security.SecureString"/> — what WPF's PasswordBox exposes —
    /// without going through a managed string.
    /// </summary>
    /// <remarks>
    /// <c>PasswordBox.Password</c> would be the obvious way to read the value and it returns a
    /// <see cref="string"/>: immutable, un-erasable, and left in the heap for the GC to move
    /// around. Marshalling the SecureString to unmanaged memory, copying into a pinned buffer, and
    /// zero-freeing the intermediate keeps the plaintext erasable end to end.
    /// </remarks>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static Secret FromSecureString(System.Security.SecureString value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var unmanaged = Marshal.SecureStringToGlobalAllocUnicode(value);
        try
        {
            return FromNativeUtf16(unmanaged, value.Length);
        }
        finally
        {
            Marshal.ZeroFreeGlobalAllocUnicode(unmanaged);
        }
    }

    /// <summary>Copies <paramref name="charCount"/> UTF-16 units out of unmanaged memory.</summary>
    internal static Secret FromNativeUtf16(IntPtr source, int charCount)
    {
        if (source == IntPtr.Zero)
        {
            throw new ArgumentNullException(nameof(source));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(charCount);

        var secret = new Secret(charCount);
        for (var i = 0; i < charCount; i++)
        {
            secret._value[i] = (char)(ushort)Marshal.ReadInt16(source, i * sizeof(char));
        }

        return secret;
    }

    public int Length => _value.Length;

    /// <summary>
    /// Exposes the plaintext. Callers must not copy it into a string, log it, or place it on a
    /// command line; write it directly to its destination stream instead.
    /// </summary>
    public ReadOnlySpan<char> Reveal()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _value;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Array.Clear(_value);
        if (_pin.IsAllocated)
        {
            _pin.Free();
        }

        _disposed = true;
    }
}
