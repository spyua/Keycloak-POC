using Jose;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace DummyTestUsage
{
    public class JWTTokenUtil
    {

        public static RSAParameters GetRSAParametersFromPublicKey(string publicKeyPath)
        {
            // 讀取公鑰文件
            string publicRsaKey = File.ReadAllText(publicKeyPath);

            using (StringReader tr = new StringReader(publicRsaKey))
            {
                PemReader pemReader = new PemReader(tr);
                RsaKeyParameters publicKeyParams = pemReader.ReadObject() as RsaKeyParameters;
                if (publicKeyParams == null)
                {
                    throw new Exception("Could not read RSA key");
                }
                return DotNetUtilities.ToRSAParameters(publicKeyParams);
            }
        }

        public static string DecryptToken(string tokenData, RSAParameters rsaParams)
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                return Jose.JWT.Decode(tokenData, rsa, JwsAlgorithm.RS256);
            }
        }



        public static string DecryptToken(string tokenData, string publicRsaKey)
        {
            RSAParameters rsaParams;
            using (StringReader tr = new StringReader(publicRsaKey))
            {
                PemReader pemReader = new PemReader(tr);
                RsaKeyParameters publicKeyParams =
                pemReader.ReadObject() as RsaKeyParameters;
                if (publicKeyParams == null)
                {
                    throw new Exception("Could not read RSA key");
                }
                rsaParams = DotNetUtilities.ToRSAParameters(publicKeyParams);
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                return Jose.JWT.Decode(tokenData, rsa,
                Jose.JwsAlgorithm.RS256);
            }
        }
    }
}
