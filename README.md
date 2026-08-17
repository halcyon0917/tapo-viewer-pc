# Tapo Viewer

A Windows desktop viewer for Tapo cameras (built and tested against a **TC40**), using only the
camera's local standards-based interfaces. No TP-Link cloud, no reverse-engineered app API, no
port forwarding.

The design goal was not "make it work" — that part is easy — but **make it work without opening a
hole**. Every security claim below was verified against real hardware rather than assumed; where
something is a genuine limitation, it is stated as one.

---

## Requirements

- Windows 10/11 x64
- .NET 8 SDK
- A Tapo camera with a **Camera Account** configured, and RTSP still enabled in its firmware

### Set up the Camera Account first

In the Tapo mobile app: **Device Settings → Advanced Settings → Camera Account**. Create a
username and password there.

This is **not** your TP-Link cloud login, and that distinction is a security feature worth
understanding: the Camera Account grants RTSP and ONVIF access to that one camera and nothing
else. If it leaks, an attacker sees one camera. If your cloud login leaked, they would have your
entire account. Never put cloud credentials into this app.

---

## Building a standalone executable

```bash
powershell -ExecutionPolicy Bypass -File .\publish.ps1
```

Produces a self-contained build that runs on a machine with **no .NET installed**:

```
artifacts\TapoViewer\
    TapoViewer.App.exe        <- run this
    decoder\
        TapoViewer.Decoder.exe
        libvlc\win-x64\
```

Roughly 330 MB, most of it libVLC. Copy the whole `TapoViewer` folder to move it —
`TapoViewer.App.exe` needs `decoder\` beside it. Right-click the exe → *Send to → Desktop* for a
shortcut.

For a much smaller build that requires the .NET 8 Desktop Runtime:

```bash
powershell -ExecutionPolicy Bypass -File .\publish.ps1 -FrameworkDependent
```

Note that `libvlc\` appears only under `decoder\`, never beside `TapoViewer.App.exe`. That is
deliberate and load-bearing: the UI process should have no libVLC binaries in its own directory.

---

## Quick start

Run the app and click **+ Add camera**:

```bash
dotnet run --project src/TapoViewer.App
```

Enter the camera's LAN address and its Camera Account credentials, then press **Test connection**
before saving — that verifies the address and password, and reports whether the camera offers PTZ
and motion events so the saved profile matches what it actually supports rather than what was
guessed. The password goes to Windows Credential Manager; `cameras.json` never contains it.

Use the **⚙** and **✕** buttons on each tile to edit or remove a camera. Removing one deletes its
stored password from Credential Manager too.

### Or provision from the command line

```bash
dotnet run --project tools/TapoViewer.Probe
```

Same result, plus a fuller report of what the camera supports. Useful when the app will not
connect and you want to see each ONVIF call individually.

### Don't know the camera's IP?

Scan your subnet for RTSP and ONVIF listeners — no credentials needed:

```bash
for i in $(seq 1 254); do (timeout 0.4 bash -c "echo > /dev/tcp/192.168.1.$i/554" 2>/dev/null && echo "OPEN 192.168.1.$i:554") & done; wait
```

### Confirm the camera speaks RTSP at all

TP-Link has gated RTSP on some newer firmware. This checks it **without a password** — an
unauthenticated `DESCRIBE` should return `401` with a `WWW-Authenticate` header naming the camera:

```bash
CAM=192.168.1.50; exec 3<>/dev/tcp/$CAM/554; printf 'DESCRIBE rtsp://%s:554/stream1 RTSP/1.0\r\nCSeq: 1\r\n\r\n' "$CAM" >&3; timeout 4 cat <&3; exec 3<&- 3>&-
```

---

## Architecture

```
┌─────────────────────────────────────────────┐
│ TapoViewer.App        (medium integrity)     │
│  · WPF grid UI, PTZ, motion toasts           │
│  · ONVIF client  ─────────────► camera:2020  │
│  · Credential Manager access                 │
└───────┬─────────────────────────────────────┘
        │ inherited stdin/stdout pipes (private)
        │ + Job Object (kill-on-close, 1 proc, 1.5 GiB)
┌───────▼─────────────────────────────────────┐
│ TapoViewer.Decoder    (LOW integrity)        │
│  · libVLC + H.264 demux/decode               │
│  · bare Win32 HWND, adopted by the UI        │
│  · RTSP/TCP  ─────────────────► camera:554   │
└─────────────────────────────────────────────┘
```

### Why the decoder is a separate process

libVLC and its demuxers are a large body of C parsing hostile input from a device on an untrusted
network. The assumption is that one day it is exploitable. At low integrity, a payload landing
there **cannot** write to your documents, read the credential vault, or inject into the UI
process, and it dies when the job handle closes.

### Why the child creates the window and the parent adopts it

Windows UIPI forbids a low-integrity process from parenting itself to a higher-integrity window,
but permits the reverse. So the sandboxed decoder creates a hidden top-level window, reports the
handle over stdout, and the privileged UI reparents and positions it. This direction is forced by
the OS, not a preference.

---

## Threat model

| Risk | Mitigation | Verified |
|---|---|---|
| Decoder RCE via malformed stream | Separate process at low integrity (`S-1-16-4096`) in a Job Object | **Yes** — token read back with `GetTokenInformation` |
| Credentials readable in process list | Delivered over inherited stdin; never argv or environment | Yes — `RtspTarget` has no password field by construction |
| Credentials in logs / crash dumps | libVLC login callback instead of `rtsp://user:pass@host`; all logging redacts | Yes |
| Weak auth scheme chosen | Camera offers **Basic before Digest**; libVLC picks Digest | **Yes** — observed in the RTSP trace |
| Camera redirects us elsewhere (SSRF) | `HostGuard.EnsureSameDevice` on every device-supplied URI | Yes — unit tested incl. redirect-to-LAN-host |
| Connecting to the internet by mistake | LAN-only address policy; DNS resolved once and pinned | Yes — unit tested |
| DNS rebinding | All resolved addresses must be private; connections use the pinned IP, not the name | Yes |
| XXE / billion laughs from camera XML | `DtdProcessing.Prohibit`, null resolver, 1 MiB response cap | Yes — CA3075 enforced as a build error |
| Plaintext secrets at rest | Windows Credential Manager; config store rejects secret-shaped fields on read **and** write | Yes — tested |
| Orphaned decoders after a UI crash | Job Object `KILL_ON_JOB_CLOSE` | Yes |
| Inbound network surface | Pull-point event subscriptions; every connection is outbound | Yes |

### Enforced at build time

`Directory.Build.props` promotes the security-relevant analyzer rules to **errors**, not warnings:
CA3075 (insecure DTD), CA5359 (disabled cert validation), CA5364/CA5386/CA5398 (weak TLS),
CA5350/CA5351 (broken crypto), plus all nullability warnings. These are exactly the mistakes that
would turn this app into the hole it exists to avoid, so they cannot be scrolled past.

---

## Network hardening

The app closes the holes it controls. These are the ones only you can close.

**1. Never port-forward 554 or 2020.** This is how cameras end up indexed on Shodan. Tapo offers
no RTSPS — the video and the Digest challenge are cleartext on the wire. It is a LAN protocol;
keep it on the LAN.

**2. Put the camera on its own VLAN or guest SSID.** The camera is an untrusted IoT device. It
should not be able to reach your PCs, your NAS, or your router's admin interface.

**3. Block the camera's outbound WAN access** at your router, unless you actively use the Tapo
app's remote features. A camera that cannot reach the internet cannot be conscripted into a
botnet or exfiltrate anything.

**4. Give the Camera Account its own password** — not one reused anywhere else.

---

## Remote viewing

Use a VPN. Both options below put your PC *on* the home LAN, so the app keeps talking to a private
address and its LAN-only policy still holds.

### Tailscale (easier)

1. Install Tailscale on the viewing PC and on any always-on machine at home (a Pi, a NAS, a
   desktop).
2. On the home machine, advertise the camera's subnet:

```bash
tailscale up --advertise-routes=192.168.1.0/24
```

3. Approve the route in the Tailscale admin console, then on the viewing PC:

```bash
tailscale up --accept-routes
```

The camera stays reachable at its normal private IP. Nothing is exposed to the internet.

### WireGuard (more control)

Run WireGuard on your router (OPNsense, OpenWrt, UniFi, or a Pi). Forward **only** the WireGuard
UDP port — typically 51820 — and set `AllowedIPs` on the client to your LAN subnet. One UDP port
with modern cryptography is a far smaller target than an RTSP server.

---

## Diagnostics

```bash
# What does the camera support? Stores credentials.
dotnet run --project tools/TapoViewer.Probe

# Does libVLC decode this stream, and which auth scheme does it pick?
dotnet run --project src/TapoViewer.Decoder -- --selftest --seconds 8

# Does the sandbox apply, and does playback survive it?
dotnet run --project tools/TapoViewer.Probe -- --sandbox-test --integrity low

# Same, at medium integrity — use if a GPU driver refuses to decode at low integrity.
dotnet run --project tools/TapoViewer.Probe -- --sandbox-test --integrity medium
```

The app writes connection diagnostics to `%LOCALAPPDATA%\TapoViewer\app.log`. It records status
and failures, never credentials.

---

## Known limitations

These are real. They are listed because a security document that only lists wins is not useful.

- **RTSP is unencrypted.** Tapo offers no RTSPS. On your LAN, anyone who can capture packets can
  watch the video. This is a camera limitation with no client-side fix; it is why the LAN-only
  policy is enforced rather than advised.
- **The decoder process holds the password as a managed string.** LibVLCSharp's `PostLogin` takes
  `System.String`, so it cannot be zeroed. Mitigated by that process being the low-integrity one
  and by the credential being a dedicated per-camera account. The privileged UI process avoids
  this: it hand-composes the credential JSON into a buffer it wipes immediately.
- **No recording.** Deliberately out of scope for v1; it would add retention, disk-quota, and
  file-permission surface.
- **One camera is edited at a time.** There is no bulk import, and no reordering of tiles beyond
  the order they appear in `cameras.json`.
- **The first media profile is used.** Cameras exposing several (`mainStream`, `minorStream`,
  `jpegStream`) are not yet selectable per tile beyond the HD/SD toggle.
- **Event subscription endpoints on dynamic ports are accepted** as long as they are on the same
  device. The camera allocates a fresh port per subscription (1024, 1025, …), so the port cannot
  be pinned — only the host can be.
- **`InvariantGlobalization` is off for the UI project.** WPF's font-cache layer constructs
  `CultureInfo("en")` during text layout and crashes without real culture data. It remains on for
  the console tools.

---

## Application icon

The icon is original artwork, not TP-Link's. This project interoperates with Tapo cameras but is
not made by, endorsed by, or affiliated with TP-Link, so it does not carry their mark — that would
misattribute authorship of this software.

It is generated rather than hand-drawn, so it stays editable:

```bash
powershell -ExecutionPolicy Bypass -File .\assets\generate-icon.ps1 -OutDir .\assets
```

That produces a multi-resolution `.ico` (16 → 256px) with the geometry retuned per size — below
about 24px the aperture ring is thickened and the pupil shrunk, because at that scale
antialiasing smears a faithfully-scaled ring and pupil into a single grey blob. Two alternates
(`alt-shield.ico`, `alt-wall.ico`) are kept alongside it.

---

## Project layout

```
src/TapoViewer.Core/       Security, ONVIF, sandbox, config, protocol  (net8.0-windows)
  Security/                Secret, credential vault, LAN address policy, HostGuard
  Onvif/                   Hand-rolled ONVIF Profile S client
  Sandbox/                 Job objects, low-integrity process launch, integrity inspector
  Decoding/                stdin/stdout protocol, decoder connection
  Configuration/           Camera profiles, secret-rejecting JSON store
src/TapoViewer.App/        WPF UI                                      (medium integrity)
src/TapoViewer.Decoder/    libVLC host                                 (low integrity)
tools/TapoViewer.Probe/    Camera + sandbox diagnostics
tests/                     xUnit tests for the Core security primitives
```

### Why the ONVIF client is hand-rolled

Generating from the ONVIF WSDLs pulls in a large SOAP stack with its own XML settings and
defaults. This app needs six operations. A few hundred lines of explicit, hardened code is
auditable; a generated stack that nobody reads is not — and "auditable" is the entire premise.
