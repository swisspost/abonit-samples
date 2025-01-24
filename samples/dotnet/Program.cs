using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Abonit.Helper.Sample;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

// Setup application
var builder = Host.CreateApplicationBuilder(args);

builder.Configuration
    .AddUserSecrets<Program>();

builder.Services
    .Configure<AbonitOptions>(builder.Configuration.GetSection(AbonitOptions.Section));
    
var host = builder.Build();

// Load options
var options = host.Services.GetRequiredService<IOptions<AbonitOptions>>().Value;

// Load the public key from Intrum AG API
var publicKey = await GetPublicKeyAsync(options.IntrumPublicKeyUrl.ToString());

// Generate secret used to encrypt Intrum AG response
var sharedSecret = GenerateSharedSecret();

// Encrypt shared secret
var encryptedSharedSecret = Encrypt(publicKey, sharedSecret);

// Send request to Post service
var worthinessResponse = await CheckWorthinessRequestAsync(options.AbonitApi, encryptedSharedSecret);

// Decrypt response
var decrypted = Decrypt(sharedSecret, worthinessResponse.CreditworthinessInfo);
Console.WriteLine(decrypted);

return;

static async Task<byte[]> GetPublicKeyAsync(string publicKeyUrl)
{
    using var client = new HttpClient();
    var publicKeyResponse = await client.GetFromJsonAsync<PublicKeyResponse>(publicKeyUrl);
    
    return Convert.FromBase64String(publicKeyResponse!.PublicKey);
}

static string GenerateSharedSecret(int size = 32)
{
    var secretBytes = RandomNumberGenerator.GetBytes(size);
    return Convert.ToBase64String(secretBytes);
}

static byte[] Encrypt(byte[] publicKey, string plainData)
{
    var plainDataBytes = Encoding.UTF8.GetBytes(plainData);
    
    using var rsa = RSA.Create();
    rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
    
    return rsa.Encrypt(plainDataBytes, RSAEncryptionPadding.OaepSHA1);
}

static async Task<WorthinessResponse> CheckWorthinessRequestAsync(
    AbonitApi options,
    byte[] encryptedSharedSecret,
    CancellationToken token = default)
{
    var serializerOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    var authRequest = new HttpRequestMessage(HttpMethod.Post, options.TokenUrl);
    authRequest.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    authRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        { "client_id", options.Secrets.ClientId },
        { "client_secret", options.Secrets.ClientSecret },
        { "grant_type", "client_credentials" },
        { "scope", options.Scope }
    });
    
    using var client = new HttpClient();
    var authResponse = await client.SendAsync(authRequest, token);
    authResponse.EnsureSuccessStatusCode();

    var tokenResponse = await authResponse.Content.ReadFromJsonAsync<TokenResponse>(serializerOptions, token);
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse!.AccessToken);
    
    var encryptedCustomerKey = Convert.ToBase64String(encryptedSharedSecret);
    var worthinessRequest = new WorthinessRequest(
        encryptedCustomerKey,
        "Eirene_maintenance_v2_L",
        10_000,
        [
            new AddressField("Prename_in", "Roth"),
            new AddressField("Name_in", "Barbara"),
            new AddressField("StreetName_in", "Unterer Quai"),
            new AddressField("HouseNo_in", "102A"),
            new AddressField("ZIPCode_in", "2502"),
            new AddressField("TownName_in", "Biel/Bienne")
        ]);
    
    var worthinessResponseMessage = await client.PostAsJsonAsync(options.WorthinessUrl, worthinessRequest, token);
    worthinessResponseMessage.EnsureSuccessStatusCode();
    
    var worthinessResponse = await worthinessResponseMessage.Content.ReadFromJsonAsync<WorthinessResponse>(token);
    return worthinessResponse!;
}

static string Decrypt(string sharedSecret, CreditworthinessInfo creditworthinessInfo)
{
    var cipherText = Convert.FromBase64String(creditworthinessInfo.CipherText);
    var associatedData = Convert.FromBase64String(creditworthinessInfo.AssociatedData);

    var iv = cipherText[..12];
    var salt = cipherText[12..28];
    var tag = cipherText[^16..];
    var encryptedData = cipherText[28..^16];

    using var deriveBytes = new Rfc2898DeriveBytes(sharedSecret, salt, 1024, HashAlgorithmName.SHA1);
    using var aes = new AesGcm(deriveBytes.GetBytes(32), tag.Length);

    var decryptedData = new byte[encryptedData.Length];
    aes.Decrypt(iv, encryptedData, tag, decryptedData, associatedData);

    return Encoding.UTF8.GetString(decryptedData);
}