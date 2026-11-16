using LanGuard.Server;
using LanGuard.Shared;
using Xunit;

namespace LanGuard.Tests;

public sealed class DetectorTests
{
    internal static SignatureCatalog Catalog => Storage.Read<SignatureCatalog>(File.ReadAllText(
        Path.Combine(AppContext.BaseDirectory, "signatures", "remote-access.json")));

    [Fact]
    public void RegistryAndServiceCorroborate()
    {
        var match = Assert.Single(Detector.MatchInventory(Catalog,
            [new("registry", "AnyDesk"), new("service", "AnyDesk")]));
        Assert.Equal("anydesk", match.FamilyId);
        Assert.Equal("medium", match.Confidence);
        Assert.Equal(2, match.Evidence.Length);
        Assert.False(match.CurrentlyRunning);
    }

    [Fact]
    public void RenamedPortableProcessMatchesMetadata()
    {
        var match = Assert.Single(Detector.MatchInventory(Catalog,
            [new("process", "meeting-helper", OriginalFilename: "rustdesk.exe", Product: "RustDesk")]));
        Assert.Equal("rustdesk", match.FamilyId);
        Assert.Equal("medium", match.Confidence);
        Assert.True(match.CurrentlyRunning);
        Assert.Equal(["originalFilename", "product"], match.Evidence[0].MatchedFields);
    }

    [Fact]
    public void PublisherAndSubstringDoNotAnchorAMatch()
    {
        Assert.Empty(Detector.MatchInventory(Catalog,
            [new("process", "backup-anydesk", Publisher: "AnyDesk Software GmbH")]));
    }

    [Fact]
    public void ExactNameWithoutCorroborationIsLowConfidence()
    {
        var match = Assert.Single(Detector.MatchInventory(Catalog, [new("process", "AnyDesk.exe")]));
        Assert.Equal("low", match.Confidence);
        Assert.Equal(["name"], match.Evidence[0].MatchedFields);
    }

    [Fact]
    public void ScheduledExecutableIsEvidenceWithoutClaimingItIsRunning()
    {
        var match = Assert.Single(Detector.MatchInventory(Catalog, [new("task", "TeamViewer_Service.exe")]));
        Assert.Equal("teamviewer", match.FamilyId);
        Assert.False(match.CurrentlyRunning);
        Assert.Equal("low", match.Confidence);
    }

    [Theory]
    [InlineData("Ammy Admin", "ammyy")]
    [InlineData("Ammyy Admin", "ammyy")]
    [InlineData("Assistent", "assistent")]
    [InlineData("Ассистент Про", "assistent")]
    [InlineData("RuDesktop", "rudesktop")]
    public void RegistryRecognizesRemoteSupportSoftware(string displayName, string familyId)
    {
        var match = Assert.Single(Detector.MatchInventory(Catalog, [new("registry", displayName)]));
        Assert.Equal(familyId, match.FamilyId);
    }

    [Fact]
    public void GenericAssistantFilenameDoesNotIdentifyAssistent()
    {
        Assert.Empty(Detector.MatchInventory(Catalog, [new("process", "assistant.exe")]));
    }
}
