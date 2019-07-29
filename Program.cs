using System;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
 

namespace PoC_DecryptJwtToken
{
    class Program
    {
        //SOPRA token for UAT and Sandbox environments
        const string token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjb21wYW55Q29kZSI6IlNCUyIsImNsaWVudElkIjoiUFNERlItTkJCLTEyMzQ1NiIsImNvbm5lY3RvcnNJbmZvcm1hdGlvbiI6e30sImF1dGhvcml6YXRpb25zIjp7fSwidXNlcklkIjoiam9obi5kb2UiLCJjbGllbnRfaWQiOiJQU0RGUi1OQkItMTIzNDU2IiwiYnVzaW5lc3NEYXRlIjoiMjAxOS0wNy0yNFQxNTozOToyNS42OTZaIiwidHBwSW5mb3JtYXRpb24iOnsiaWQiOiI1ZDM4N2EyOTU2M2JlZDAwMDFhNWE2ZWYiLCJuYW1lIjoiUFNERlItTkJCLTEyMzQ1NiIsImFjY3JlZGl0YXRpb25zIjpbIkFJUyIsIkNJUyIsIlBJUyJdfSwiZGVsZWdhdGVJZCI6IkFnZW50NTUiLCJzY29wZSI6WyJmYWxsYmFjayJdLCJ0ZW5hbnRJZCI6IlNPUFJBIiwidXNlclR5cGUiOiJUUFAiLCJleHAiOjE1NjQ4NDY3NjUsImp0aSI6Ijg1ZTI3YTU2LTQyNTgtNGE5MC1hMzliLTAxNGM3ZTljOTg5NyJ9.RBoSWXupnDhOJSgc74KzSoqHR_MXTGH2p28mcr-TmwbVo77UFhD1-1FvcT8U4Lkxd4EAcTvAGAuWhqog3cz4Qhc--vGl_Jw8CKTT42kGp3CMm1sil958mR2WiEDgpH-9ozJObjhdBkXEKHLFAfOISVsSY2u9J0Y2s8OsUlswx-InGcSx_l0jxdeAio9YAVOZxh7YwLhLa7g9mM9y90ejffsN8t9iXYvuQ_EYdimPFsmV-i6i7SuHn1eb3-LP1ujSAnVgQWU3k4vIOyqRdSI9AdyYbqwR8xIxuxh5rc4iFg9l3TRRxP_qTTgHGpxx7GME1-R_C9nGM43yRIPN1LDuXw";
        
        //SOPA pub key to verify signature
        const string pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxCYlXLtL3C/uWbaAgL9BX2DczN3erpmUbZVLX3ZTMWJu5wmCrRYjRbDKFZc2T8CxXHGpye/T9usL798evpQqjUi6sgVnjkzyhuOqDK8KPipR8Q9D37kwRH4KjJczD6mv7slVn/rWBP6zUwAca9hy4hLulRiIuQrLIDaGR+CwTI/1AI9rDb3rLraO6cImJ2a9qETEzgoJUTrrjEZDag30pBNaG+oemNK0ZhWS8onD6nvxJMkERhYyLs4LJ/LAcZ5qJCBWoJRFX2Hgq+o8vmXAkO8vPUfksavnlyBm4BY3sWBEDainERVZajLFNkv2XABqlMrjpdHVqWSRReX7eXXW9wIDAQAB";


        static void Main(string[] args)
        {
            var keyBytes = Convert.FromBase64String(pubKey);

            try
            {
                var x = Decode(token, pubKey);
                Console.WriteLine(x);
            }
            catch (Exception e)
            {
                Console.WriteLine("invalid");
            }      
        }

        public static string Decode(string token, string key, bool verify = true)
        {
            var parts = token.Split('.');
            var header = parts[0];
            var payload = parts[1];
            var crypto = Base64UrlDecode(parts[2]);
        
            var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            var headerData = JObject.Parse(headerJson);
        
            var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            var payloadData = JObject.Parse(payloadJson);
        
            if (verify)
            {
                var keyBytes = Convert.FromBase64String(key); // your key here
        
                var asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
                var rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
                var rsaParameters = new RSAParameters();
                rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
                rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParameters);
        
                var sha256 = SHA256.Create();
                var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));
        
                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");
                if (!rsaDeformatter.VerifySignature(hash, FromBase64Url(parts[2])))
                    throw new ApplicationException(string.Format("Invalid signature"));
            }
        
            return payloadData.ToString();
        }

        // from JWT spec
        static byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 1: output += "==="; break; // Three pad chars
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }

        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
    }
}
