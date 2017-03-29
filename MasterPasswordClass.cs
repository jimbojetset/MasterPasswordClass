using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CryptSharp.Utility;
using System.Security.Cryptography;
using System.Security;

class MasterPasswordClass
{
    private static byte[] keyScopeBytes = Encoding.UTF8.GetBytes("com.lyndir.masterpassword");
    private const int _N = 32768;
    private const int _r = 8;
    private const int _p = 2;
    private const int _dkLen = 64;
    private static Dictionary<char, string> passChars = new Dictionary<char, string>()
    {
        {'V', "AEIOU"},
        {'v', "aeiou"},
        {'C', "BCDFGHJKLMNPQRSTVWXYZ"},
        {'c', "bcdfghjklmnpqrstvwxyz"},
        {'A', "AEIOUBCDFGHJKLMNPQRSTVWXYZ"},
        {'a', "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz"},
        {'n', "0123456789"},
        {'o', "@&%?,=[]_:-+*$#!\'^~;()/."},
        {'x', "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()"},
        {' ', " "}
    };
    private static Dictionary<templateTypes, string[]> templates = new Dictionary<templateTypes, string[]>()
    {
        {templateTypes.Max, new string[]{ "anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"} },
        {templateTypes.Long, new string[]{ "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv", "CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv", "CvcvCvccnoCvcv", "CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno", "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno", "CvcvnoCvccCvcc", "CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc", "CvccCvcvCvccno" } },
        {templateTypes.Medium, new string[]{ "CvcnoCvc", "CvcCvcno" } },
        {templateTypes.Basic, new string[]{ "aaanaaan", "aannaaan", "aaannaaa" } },
        {templateTypes.Short, new string[]{ "Cvcn" } },
        {templateTypes.PIN, new string[]{ "nnnn" } },
        {templateTypes.Name, new string[]{ "cvccvcvcv" } },
        {templateTypes.Phrase, new string[]{ "cvcc cvc cvccvcv cvc", "cvc cvccvcvcv cvcv", "cv cvccv cvc cvcvccv" } },
    };

    public enum templateTypes
    {
        Max,
        Long,
        Medium,
        Basic,
        Short,
        PIN,
        Name,
        Phrase,
    }

    public MasterPasswordClass()
    {
    }

    public string GetPasswordPattern(SecureString userName, SecureString masterPassword, SecureString site, int counter = 1, templateTypes template = templateTypes.Long)
    {
        byte[] masterKey = GetMasterKey(userName, masterPassword);
        byte[] templateSeed = GetTemplateSeed(masterKey, site, counter);
        string pattern = GetPattern(templateSeed, template);
        return pattern;
    }

    private static byte[] GetMasterKey(SecureString userName, SecureString masterPassword)
    {
        byte[] userNameBytes = Encoding.UTF8.GetBytes(new System.Net.NetworkCredential(string.Empty, userName).Password);
        byte[] userNameLengthBytes = BitConverter.GetBytes(userNameBytes.Length);
        Array.Reverse(userNameLengthBytes);
        byte[] salt = keyScopeBytes.Concat(userNameLengthBytes).Concat(userNameBytes).ToArray();
        byte[] masterPasswordBytes = Encoding.UTF8.GetBytes(new System.Net.NetworkCredential(string.Empty, masterPassword).Password);
        byte[] masterKey = SCrypt.ComputeDerivedKey(masterPasswordBytes, salt, _N, _r, _p, null, _dkLen);
        return masterKey;
    }

    private static byte[] GetTemplateSeed(byte[] masterKey, SecureString site, int counter)
    {
        byte[] siteBytes = Encoding.UTF8.GetBytes(new System.Net.NetworkCredential(string.Empty, site).Password);
        byte[] siteLengthBytes = BitConverter.GetBytes(site.Length);
        Array.Reverse(siteLengthBytes);
        byte[] counterBytes = BitConverter.GetBytes(counter);
        Array.Reverse(counterBytes);
        byte[] concatenated = keyScopeBytes.Concat(siteLengthBytes).Concat(siteBytes).Concat(counterBytes).ToArray();
        HMACSHA256 hmacsha265 = new HMACSHA256(masterKey);
        byte[] seed = hmacsha265.ComputeHash(concatenated);
        return seed;
    }

    private static string GetPattern(byte[] seed, templateTypes templateType)
    {
        int cnt = 0;
        string[] template = templates[templateType];
        string pattern = template[(int)seed[0] % template.Length];
        StringBuilder sb = new StringBuilder();
        foreach (char c in pattern)
        {
            string s = passChars[c];
            sb.Append(s[(int)seed[cnt + 1] % s.Length]);
            cnt++;
        }
        return sb.ToString();
    }

   public SecureString GenerateSecureString(string value)
    {
        char[] chars = value.ToCharArray();
        SecureString secureChars = new SecureString();
        foreach (char c in chars)
            secureChars.AppendChar(c);
        return secureChars;
    }
}
