namespace Abonit.Helper.Sample;

public sealed class AbonitOptions
{
    public static string Section => "Abonit";
    
    public required Uri IntrumPublicKeyUrl { get; init; }
    public required AbonitApi AbonitApi { get; init; }
}

public sealed class AbonitApi
{
    public required Uri TokenUrl { get; init; }
    public required Uri WorthinessUrl { get; init; }
    public required Secrets Secrets { get; init; }
    public required string Scope { get; init; }
}

public sealed class Secrets
{
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
}