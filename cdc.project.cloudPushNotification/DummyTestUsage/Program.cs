// See https://aka.ms/new-console-template for more information
using DummyTestUsage;
using System.Security.Cryptography;

Console.WriteLine("Hello, World!");


string tokenData = "your-jwt-token";
string publicKeyPath = "Security/public_key.pem"; // 根據實際情況調整路徑
RSAParameters rsaParams = JWTTokenUtil.GetRSAParametersFromPublicKey(publicKeyPath);
string decryptedToken = JWTTokenUtil.DecryptToken(tokenData, rsaParams);
Console.WriteLine(decryptedToken);