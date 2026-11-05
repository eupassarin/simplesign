using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Markup.Xaml;
using Avalonia.Platform.Storage;
using SimpleSign.Desktop.ViewModels;

namespace SimpleSign.Desktop.Controls;

/// <summary>Drag-and-drop zone: drop a file, or click to pick one.</summary>
internal sealed partial class DropZone : UserControl
{
    public static readonly StyledProperty<string?> FileNameProperty = AvaloniaProperty.Register<DropZone, string?>(nameof(FileName));

    public static readonly StyledProperty<string> HintProperty = AvaloniaProperty.Register<DropZone, string>(nameof(Hint), "ou clique para escolher");

#pragma warning disable CS0618 // The 11.x DataTransfer API is still new; the classic drag-and-drop API works everywhere.
    public DropZone()
    {
        AvaloniaXamlLoader.Load(this);
        var zone = this.FindControl<Border>("Zone")!;
        zone.AddHandler(DragDrop.DragOverEvent, (_, e) =>
        {
            e.DragEffects = e.Data.Contains(DataFormats.Files) ? DragDropEffects.Copy : DragDropEffects.None;
            zone.BorderBrush = SimpleSign.Desktop.Views.Converters.Brush("App.Accent");
        });
        zone.AddHandler(DragDrop.DragLeaveEvent, (_, _) => zone.BorderBrush = SimpleSign.Desktop.Views.Converters.Brush("App.Separator"));
        zone.AddHandler(DragDrop.DropEvent, async (_, e) =>
        {
            zone.BorderBrush = SimpleSign.Desktop.Views.Converters.Brush("App.Separator");
            if (e.Data.GetFiles()?.FirstOrDefault()?.TryGetLocalPath() is { } path && DataContext is IFileDropTarget target)
            {
                await target.LoadFileAsync(path);
            }
        });
        zone.PointerReleased += (_, _) =>
        {
            if (DataContext is IFileDropTarget target && target.DropPickCommand.CanExecute(null))
            {
                target.DropPickCommand.Execute(null);
            }
        };
        PropertyChanged += (_, e) =>
        {
            if (e.Property == FileNameProperty || e.Property == HintProperty)
            {
                this.FindControl<TextBlock>("Headline")!.Text = FileName ?? "Arraste um arquivo aqui";
                this.FindControl<TextBlock>("HintText")!.Text = FileName is null ? Hint : "Clique ou arraste para trocar";
            }
        };
    }

#pragma warning restore CS0618

    public string? FileName
    {
        get => GetValue(FileNameProperty);
        set => SetValue(FileNameProperty, value);
    }

    public string Hint
    {
        get => GetValue(HintProperty);
        set => SetValue(HintProperty, value);
    }
}
