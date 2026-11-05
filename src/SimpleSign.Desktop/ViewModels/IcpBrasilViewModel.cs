using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SimpleSign.Brasil.IcpBrasil;
using SimpleSign.Brasil.Xades;
using SimpleSign.Desktop.Services;

namespace SimpleSign.Desktop.ViewModels;

internal sealed record PolicyRow(string Name, string Version, string Oid, string Period, string Roots, bool InForce, bool Revoked)
{
    public string State => Revoked ? "Revogada" : InForce ? "Vigente" : "Fora do período";
}

internal sealed record RootRow(string Name, string Expires, bool ExpiringSoon);

internal sealed partial class IcpBrasilViewModel : PageViewModel
{
    public IcpBrasilViewModel(AppServices services)
        : base(services, "ICP-Brasil", "Políticas de assinatura (LPA), raízes aceitas por política e cadeia de homologação.", "Icon.Brasil")
    {
        _selectedFormat = Formats[0];
        _homologation = services.Settings.Current.IcpHomologation;
        LoadPolicies();
        foreach (var root in IcpBrasilChainValidator.LoadBundledAcRaizCerts().OrderBy(r => r.NotAfter))
        {
            Roots.Add(new RootRow(root.GetNameInfo(X509NameType.SimpleName, false), root.NotAfter.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture),
                root.NotAfter < DateTime.Now.AddYears(3)));
        }
    }

    public IReadOnlyList<Option<IcpBrasilPolicyFormat>> Formats { get; } =
    [
        new(IcpBrasilPolicyFormat.Pades, "PAdES"),
        new(IcpBrasilPolicyFormat.Cades, "CAdES"),
        new(IcpBrasilPolicyFormat.Xades, "XAdES"),
    ];

    public ObservableCollection<PolicyRow> Policies { get; } = [];

    public ObservableCollection<RootRow> Roots { get; } = [];

    [ObservableProperty]
    private Option<IcpBrasilPolicyFormat> _selectedFormat;

    [ObservableProperty]
    private bool _onlyInForce = true;

    [ObservableProperty]
    private bool _homologation;

    [ObservableProperty]
    private string? _lpaStatus;

    partial void OnSelectedFormatChanged(Option<IcpBrasilPolicyFormat> value) => LoadPolicies();

    partial void OnOnlyInForceChanged(bool value) => LoadPolicies();

    partial void OnHomologationChanged(bool value)
    {
        Services.Settings.Current.IcpHomologation = value;
        Services.Settings.Save();
        StatusMessage = value ? "Certificados de homologação serão aceitos (não valem em produção)." : "Somente a cadeia de produção.";
    }

    private void LoadPolicies()
    {
        Policies.Clear();
        var now = DateTimeOffset.UtcNow;
        foreach (var p in IcpBrasilSignaturePolicies.All
            .Where(p => p.Info.Format == SelectedFormat.Value && (!OnlyInForce || p.IsValidAt(now)))
            .OrderBy(p => p.Info.Policy).ThenByDescending(p => p.NotBefore))
        {
            string roots = IcpBrasilSignaturePolicies.TryGetRules(p.Oid, out var rules)
                ? string.Join(", ", rules.TrustAnchorSubjects.Select(RootVersion))
                : "-";
            Policies.Add(new PolicyRow(Options.PolicyName(p.Info.Policy), p.Info.Version ?? "-", p.Oid,
                $"{p.NotBefore:dd/MM/yyyy} – {(p.NotAfter == DateTimeOffset.MaxValue ? "…" : p.NotAfter.ToString("dd/MM/yyyy", CultureInfo.InvariantCulture))}",
                roots, p.IsValidAt(now), p.RevokedAt is not null));
        }
    }

    private static string RootVersion(string subject)
    {
        int index = subject.IndexOf("Brasileira", StringComparison.Ordinal);
        if (index < 0)
        {
            return subject;
        }

        string rest = subject[(index + "Brasileira".Length)..].Trim();
        int comma = rest.IndexOf(',', StringComparison.Ordinal);
        return comma < 0 ? rest : rest[..comma];
    }

    [RelayCommand]
    private Task RefreshLpasAsync() => RunAsync(async () =>
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        var pades = await IcpBrasilSignaturePolicies.RefreshAsync(http, IcpBrasilPolicyFormat.Pades);
        var cades = await IcpBrasilSignaturePolicies.RefreshAsync(http, IcpBrasilPolicyFormat.Cades);
        var xades = await IcpBrasilXadesPolicies.RefreshAsync(http);
        LpaStatus = $"LPAs verificadas (assinatura do ITI) e aplicadas: PAdES {pades.Entries.Count}, CAdES {cades.Entries.Count}, XAdES {xades.Entries.Count}. "
            + $"Próxima atualização: {new[] { pades.NextUpdate, cades.NextUpdate, xades.NextUpdate }.Min():dd/MM/yyyy}.";
        LoadPolicies();
        Services.Log.Add(Title, LpaStatus);
    });
}
