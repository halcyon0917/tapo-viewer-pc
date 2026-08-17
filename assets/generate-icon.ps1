# Renders original app-icon candidates at every size Windows asks for, then packs a multi-image
# .ico. Each size is drawn directly rather than downscaled: a 16px icon needs proportionally
# thicker strokes and less detail, which resampling a 256px master cannot give you.
param(
    [string]$OutDir = '.',
    [int[]]$Sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function New-RoundedPath([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

function New-Canvas([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)
    return @($bmp, $g)
}

function Add-Tile($g, [int]$s, $c1, $c2) {
    # Squircle-ish tile with a diagonal gradient — the Windows 11 app-icon convention.
    $pad = [single]($s * 0.045)
    $side = [single]($s - 2 * $pad)
    $radius = [single]($s * 0.22)
    $path = New-RoundedPath $pad $pad $side $side $radius
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.PointF($pad, $pad)),
        (New-Object System.Drawing.PointF(($pad + $side), ($pad + $side))),
        $c1, $c2)
    $g.FillPath($brush, $path)
    $brush.Dispose()
    $path.Dispose()
}

# ---- Candidate A: aperture lens ------------------------------------------------------------
function Draw-Lens([int]$s) {
    $r = New-Canvas $s
    $bmp = $r[0]; $g = $r[1]
    Add-Tile $g $s ([System.Drawing.Color]::FromArgb(255, 56, 189, 248)) ([System.Drawing.Color]::FromArgb(255, 29, 78, 216))

    $cx = $s / 2.0; $cy = $s / 2.0

    # Small sizes are not the large design scaled down. Below ~24px the ring and the pupil are
    # only a couple of pixels apart, and antialiasing smears them into one grey donut. So the
    # ring gets thicker, its radius grows, and the pupil shrinks — trading fidelity for a gap
    # that survives rasterisation.
    if ($s -le 20) {
        $outer = [single]($s * 0.335)
        $ringW = [single]([Math]::Max($s * 0.125, 2.0))
        $pupilR = [single]($s * 0.080)
    }
    elseif ($s -le 32) {
        $outer = [single]($s * 0.315)
        $ringW = [single]($s * 0.100)
        $pupilR = [single]($s * 0.100)
    }
    else {
        $outer = [single]($s * 0.300)
        $ringW = [single]($s * 0.085)
        $pupilR = [single]($s * 0.115)
    }

    $white = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 255, 255, 255)), $ringW
    $white.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $white.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
    $g.DrawEllipse($white, $cx - $outer, $cy - $outer, $outer * 2, $outer * 2)

    $fill = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 255, 255, 255))
    $g.FillEllipse($fill, $cx - $pupilR, $cy - $pupilR, $pupilR * 2, $pupilR * 2)

    # Recording tick at top-right, dropped below 24px where it would just be noise.
    if ($s -ge 24) {
        $tr = [single]($s * 0.055)
        $tx = [single]($cx + $outer * 0.80); $ty = [single]($cy - $outer * 0.80)
        $g.FillEllipse($fill, $tx - $tr, $ty - $tr, $tr * 2, $tr * 2)
    }

    $white.Dispose(); $fill.Dispose(); $g.Dispose()
    return $bmp
}

# ---- Candidate B: shield + lens ------------------------------------------------------------
function Draw-Shield([int]$s) {
    $r = New-Canvas $s
    $bmp = $r[0]; $g = $r[1]
    Add-Tile $g $s ([System.Drawing.Color]::FromArgb(255, 45, 212, 191)) ([System.Drawing.Color]::FromArgb(255, 30, 64, 175))

    # Shield silhouette: flat shoulders, tapered point.
    $w = [single]($s * 0.44); $h = [single]($s * 0.50)
    $cx = $s / 2.0
    $top = [single]($s * 0.24)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddLine($cx - $w / 2, $top, $cx + $w / 2, $top)
    $path.AddBezier(
        ($cx + $w / 2), $top,
        ($cx + $w / 2), ($top + $h * 0.55),
        ($cx + $w * 0.22), ($top + $h * 0.92),
        $cx, ($top + $h))
    $path.AddBezier(
        $cx, ($top + $h),
        ($cx - $w * 0.22), ($top + $h * 0.92),
        ($cx - $w / 2), ($top + $h * 0.55),
        ($cx - $w / 2), $top)
    $path.CloseFigure()

    $fill = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 255, 255, 255))
    $g.FillPath($fill, $path)
    $path.Dispose()

    # Punch the lens out of the shield so it stays legible when small.
    $hole = [single]($s * 0.095)
    $cut = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.PointF(0, 0)),
        (New-Object System.Drawing.PointF($s, $s)),
        [System.Drawing.Color]::FromArgb(255, 45, 212, 191),
        [System.Drawing.Color]::FromArgb(255, 30, 64, 175))
    $g.FillEllipse($cut, $cx - $hole, ($top + $h * 0.40) - $hole, $hole * 2, $hole * 2)

    $fill.Dispose(); $cut.Dispose(); $g.Dispose()
    return $bmp
}

# ---- Candidate C: wall of panes -------------------------------------------------------------
function Draw-Wall([int]$s) {
    $r = New-Canvas $s
    $bmp = $r[0]; $g = $r[1]
    Add-Tile $g $s ([System.Drawing.Color]::FromArgb(255, 96, 165, 250)) ([System.Drawing.Color]::FromArgb(255, 30, 27, 122))

    # Four panes, one "live" — the multi-camera wall this app actually is.
    $gap = [single]($s * 0.055)
    $side = [single]($s * 0.185)
    $rad = [single]([Math]::Max($s * 0.035, 1))
    $x0 = [single]($s / 2.0 - $side - $gap / 2)
    $y0 = [single]($s / 2.0 - $side - $gap / 2)

    $dim = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(150, 255, 255, 255))
    $lit = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 255, 255, 255))

    for ($row = 0; $row -lt 2; $row++) {
        for ($col = 0; $col -lt 2; $col++) {
            $x = $x0 + $col * ($side + $gap)
            $y = $y0 + $row * ($side + $gap)
            $p = New-RoundedPath $x $y $side $side $rad
            $brush = if ($row -eq 0 -and $col -eq 0) { $lit } else { $dim }
            $g.FillPath($brush, $p)
            $p.Dispose()
        }
    }

    $dim.Dispose(); $lit.Dispose(); $g.Dispose()
    return $bmp
}

function Save-Ico([string]$path, [System.Collections.IList]$pngBytesList, [int[]]$sizeList) {
    $fs = [System.IO.File]::Create($path)
    $bw = New-Object System.IO.BinaryWriter($fs)
    $n = $pngBytesList.Count

    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$n)

    # Directory entries precede all image data, so offsets start after the whole table.
    $offset = 6 + (16 * $n)
    for ($i = 0; $i -lt $n; $i++) {
        $sz = $sizeList[$i]
        $dim = if ($sz -ge 256) { 0 } else { $sz }
        $bw.Write([byte]$dim); $bw.Write([byte]$dim)
        $bw.Write([byte]0); $bw.Write([byte]0)
        $bw.Write([uint16]1); $bw.Write([uint16]32)
        $bw.Write([uint32]$pngBytesList[$i].Length)
        $bw.Write([uint32]$offset)
        $offset += $pngBytesList[$i].Length
    }
    foreach ($b in $pngBytesList) { $bw.Write($b) }

    $bw.Flush(); $bw.Close(); $fs.Close()
}

$designs = @{ 'lens' = 'Draw-Lens'; 'shield' = 'Draw-Shield'; 'wall' = 'Draw-Wall' }

foreach ($name in $designs.Keys) {
    $fn = $designs[$name]
    $pngs = New-Object System.Collections.ArrayList
    foreach ($sz in $Sizes) {
        $bmp = & $fn $sz
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        [void]$pngs.Add($ms.ToArray())
        $ms.Dispose()
        if ($sz -eq 256) { $bmp.Save((Join-Path $OutDir "preview-$name.png"), [System.Drawing.Imaging.ImageFormat]::Png) }
        if ($sz -eq 32)  { $bmp.Save((Join-Path $OutDir "preview-$name-32.png"), [System.Drawing.Imaging.ImageFormat]::Png) }
        if ($sz -eq 16)  { $bmp.Save((Join-Path $OutDir "preview-$name-16.png"), [System.Drawing.Imaging.ImageFormat]::Png) }
        $bmp.Dispose()
    }
    Save-Ico (Join-Path $OutDir "$name.ico") $pngs $Sizes
    Write-Output "built $name.ico ($($Sizes.Count) sizes)"
}
