using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace TapoViewer.App.ViewModels;

/// <summary>Visible when the bound boolean is <see langword="false"/>.</summary>
public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is bool flag && !flag ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => Binding.DoNothing;
}
