using System.Windows;
using TapoViewer.App.Dialogs;
using TapoViewer.App.ViewModels;
using TapoViewer.Core.Configuration;
using TapoViewer.Core.Security;

namespace TapoViewer.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();

        // The view model is owned by DataContext rather than a field, so this window is not
        // itself a disposable-owning type; it is disposed via the Closed handler below.
        var viewModel = new MainViewModel(new CameraConfigStore(), new WindowsCredentialVault(), Dispatcher);

        // The view owns windows; the view model owns persistence. These two callbacks are the
        // whole seam between them.
        viewModel.RequestEditor = existing =>
        {
            var editor = new CameraEditorWindow(existing) { Owner = this };
            return editor.ShowDialog() == true ? editor.Result : null;
        };

        viewModel.RequestConfirmation = message => MessageBox.Show(
            this,
            message,
            "Tapo Viewer",
            MessageBoxButton.OKCancel,
            MessageBoxImage.Warning) == MessageBoxResult.OK;

        DataContext = viewModel;

        Loaded += async (_, _) => await viewModel.ReloadAsync().ConfigureAwait(true);

        // Every decoder must be torn down explicitly. The job objects would kill them on process
        // exit anyway, but doing it here means RTSP sessions are closed politely rather than the
        // camera waiting for its 15-second session timeout to lapse.
        Closed += (_, _) => viewModel.Dispose();
    }
}
