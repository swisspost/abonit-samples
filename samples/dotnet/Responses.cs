namespace Abonit.Helper.Sample;

public sealed record PublicKeyResponse(
    string PublicKey,
    DateTime ExpirationTimestamp,
    string Fingerprint);

public sealed record TokenResponse(
    string AccessToken,
    string TokenType,
    int ExpiresIn);

public sealed record WorthinessRequest(
    string EncryptedSecretKey,
    string AlignmentType,
    int TimeOutSecond,
    IEnumerable<AddressField> Address);
    
public sealed record AddressField(
    string Field,
    string Value);
    
public sealed record WorthinessResponse(
    CreditworthinessInfo CreditworthinessInfo,
    string SettlementId,
    IEnumerable<AddressField> Result);

public sealed record CreditworthinessInfo(
    string CipherText,
    string AssociatedData);