namespace SimpleSign.Desktop.ViewModels;

/// <summary>A page whose documents can be dropped on it (see Controls/DropZone).</summary>
internal interface IFileDropTarget
{
    Task LoadFileAsync(string path);

    System.Windows.Input.ICommand DropPickCommand { get; }
}
