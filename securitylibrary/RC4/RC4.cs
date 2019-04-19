using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            int zz = 'Ï';
            char xx = (char)zz;
            int[] S = new int[256];
            int[] T = new int[256];
            int[] plainInt;
            int[] keyInt;
            int[] cipherInt;
            if (key.StartsWith("0x"))
                keyInt = HexToInt(key);
            else
                keyInt = CharToInt(key);
            if (cipherText.StartsWith("0x"))
                cipherInt = HexToInt(cipherText);
            else
                cipherInt = CharToInt(cipherText);
            #region Initialization of S & T
            int keyLen = 0;
            for (int i = 0; i < 256; i++)
            {
                S[i] = i;
                T[i] = keyInt[keyLen];
                keyLen = (keyLen + 1) % keyInt.Length;
            }
            #endregion
            #region Initial permutation of S
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
            #endregion
            #region Stream Generation
            int a = 0, b = 0;
            plainInt = new int[cipherInt.Length];
            for (int i = 0; i < plainInt.Length; i++)
            {
                a = (a + 1) % 256;
                b = (b + S[a]) % 256;
                int temp = S[a];
                S[a] = S[b];
                S[b] = temp;
                int t = (S[a] + S[b]) % 256;
                plainInt[i] = cipherInt[i] ^ S[t];
            }
            #endregion
            string plain = "";
            if (cipherText.StartsWith("0x"))
                plain = "0x" + IntToHex(plainInt);
            else
                plain = IntToChar(plainInt);
            return plain;
        }

        public override  string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            int zz = 'Ï';
            char xx = (char)zz;
            int[] S = new int[256];
            int[] T = new int[256];
            int[] plainInt;
            int[] keyInt;
            int[] cipherInt;
            if (key.StartsWith("0x"))
                keyInt = HexToInt(key);
            else
                keyInt = CharToInt(key);
            if (plainText.StartsWith("0x"))
                plainInt = HexToInt(plainText);
            else
                plainInt = CharToInt(plainText);
            #region Initialization of S & T
            int keyLen = 0;
            for(int i = 0; i < 256; i++)
            {
                S[i] = i;
                T[i] = keyInt[keyLen];
                keyLen = (keyLen + 1) % keyInt.Length;
            }
            #endregion
            #region Initial permutation of S
            int j = 0;
            for(int i=0;i<256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
            #endregion
            #region Stream Generation
            int a = 0, b = 0;
            cipherInt = new int[plainInt.Length];
            for(int i = 0; i < plainInt.Length; i++)
            {
                a = (a + 1) % 256;
                b = (b + S[a]) % 256;
                int temp = S[a];
                S[a] = S[b];
                S[b] = temp;
                int t = (S[a] + S[b]) % 256;
                cipherInt[i] = plainInt[i] ^ S[t];
            }
            #endregion
            string cipher = "";
            if (plainText.StartsWith("0x"))
                cipher = "0x" + IntToHex(cipherInt);
            else
                cipher = IntToChar(cipherInt);
            return cipher;
        }
        private int[] HexToInt(string s)
        {
            List<int> intArr = new List<int>();
            for(int i = 2; i < s.Length; i += 2)
                intArr.Add(int.Parse(s[i].ToString() + s[i + 1].ToString(), System.Globalization.NumberStyles.HexNumber));
            return intArr.ToArray();
        }
        private int[] CharToInt(string s)
        {
            List<int> intArr = new List<int>();
            for (int i = 0; i < s.Length; i++)
                intArr.Add(s[i]);
            return intArr.ToArray();
        }
        private string IntToChar(int[] arr)
        {
            string s = "";
            for (int i = 0; i < arr.Length; i++)
                s += (char)arr[i];
            return s;
        }
        private string IntToHex(int[] arr)
        {
            string s = "";
            for (int i = 0; i < arr.Length; i++)
                s += arr[i].ToString("x2");
            return s;
        }
    }
}
