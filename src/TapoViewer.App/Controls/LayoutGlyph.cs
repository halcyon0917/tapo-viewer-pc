using System.Windows;
using System.Windows.Media;

namespace TapoViewer.App.Controls;

/// <summary>
/// An n×n grid of rounded cells, used as the icon on the layout selector.
/// </summary>
/// <remarks>
/// Drawn rather than taken from an icon font. Segoe Fluent has grid glyphs, but not a matched
/// 1/4/9 set — mixing unrelated glyphs gives three icons with different weights and optical
/// sizes sitting next to each other. Drawing them from one rule keeps the outer bounds and the
/// gaps identical across all three, so only the subdivision changes.
///
/// Cell geometry is computed then rounded to whole device pixels: at this size a 4px cell landing
/// on a half-pixel boundary renders as a 5px grey smear, which is exactly the mush that makes
/// small UI look cheap.
/// </remarks>
public sealed class LayoutGlyph : FrameworkElement
{
    public static readonly DependencyProperty ColumnsProperty = DependencyProperty.Register(
        nameof(Columns),
        typeof(int),
        typeof(LayoutGlyph),
        new FrameworkPropertyMetadata(2, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty FillProperty = DependencyProperty.Register(
        nameof(Fill),
        typeof(Brush),
        typeof(LayoutGlyph),
        new FrameworkPropertyMetadata(Brushes.White, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ExtentProperty = DependencyProperty.Register(
        nameof(Extent),
        typeof(double),
        typeof(LayoutGlyph),
        new FrameworkPropertyMetadata(
            16.0,
            FrameworkPropertyMetadataOptions.AffectsMeasure | FrameworkPropertyMetadataOptions.AffectsRender));

    /// <summary>Cells per side: 1, 2 or 3.</summary>
    public int Columns
    {
        get => (int)GetValue(ColumnsProperty);
        set => SetValue(ColumnsProperty, value);
    }

    public Brush Fill
    {
        get => (Brush)GetValue(FillProperty);
        set => SetValue(FillProperty, value);
    }

    /// <summary>Width and height of the whole glyph, in device-independent pixels.</summary>
    public double Extent
    {
        get => (double)GetValue(ExtentProperty);
        set => SetValue(ExtentProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize) => new(Extent, Extent);

    protected override void OnRender(DrawingContext drawingContext)
    {
        var brush = Fill;
        if (brush is null)
        {
            return;
        }

        var columns = Math.Clamp(Columns, 1, 4);

        // Work in device pixels so cell edges land on pixel boundaries at any DPI.
        var scale = VisualTreeHelper.GetDpi(this).DpiScaleX;
        if (scale <= 0)
        {
            scale = 1.0;
        }

        // Optical correction. A single filled square covers the whole box, while a subdivided
        // grid loses area to its gaps — so at identical bounds the 1×1 reads noticeably heavier
        // than the 2×2 and 3×3 beside it. Insetting it slightly evens out the apparent weight;
        // matching the geometry exactly would look wrong even though it measures right.
        var inset = columns == 1 ? 0.86 : 1.0;
        var extentPx = Math.Round(Extent * scale * inset);
        var gapPx = columns == 1 ? 0 : Math.Max(Math.Round(2 * scale), 1);
        var cellPx = Math.Floor((extentPx - gapPx * (columns - 1)) / columns);

        if (cellPx < 1)
        {
            cellPx = 1;
        }

        // Re-centre against the FULL box, not the inset one, so all three glyphs share a centre.
        var fullExtentPx = Math.Round(Extent * scale);
        var usedPx = cellPx * columns + gapPx * (columns - 1);
        var originPx = Math.Round((fullExtentPx - usedPx) / 2);

        var cell = cellPx / scale;
        var gap = gapPx / scale;
        var origin = originPx / scale;
        var radius = Math.Max(cell * 0.18, 0.5);

        for (var row = 0; row < columns; row++)
        {
            for (var column = 0; column < columns; column++)
            {
                var rect = new Rect(
                    origin + column * (cell + gap),
                    origin + row * (cell + gap),
                    cell,
                    cell);

                drawingContext.DrawRoundedRectangle(brush, null, rect, radius, radius);
            }
        }
    }
}
