using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string cipher = "";
            key = key.Remove(0, 2);
            plainText = plainText.Remove(0, 2);
            List<string[,]> keys = new List<string[,]>();
            #region Key Generator
            string keyTemp = key;
            string[,] temp = new string[4, 4];
            int count = 0;
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    temp[j, i] = key[count++].ToString() + key[count++].ToString();
            Dictionary<string, string> sbox = new Dictionary<string, string>();
            sbox.Add("00", "63"); sbox.Add("01", "7c"); sbox.Add("02", "77"); sbox.Add("03", "7b"); sbox.Add("04", "f2");
            sbox.Add("05", "6b"); sbox.Add("06", "6f"); sbox.Add("07", "c5"); sbox.Add("08", "30"); sbox.Add("09", "01");
            sbox.Add("0a", "67"); sbox.Add("0b", "2b"); sbox.Add("0c", "fe"); sbox.Add("0d", "d7"); sbox.Add("0e", "ab"); sbox.Add("0f", "76");
            sbox.Add("10", "ca"); sbox.Add("11", "82"); sbox.Add("12", "c9"); sbox.Add("13", "7d"); sbox.Add("14", "fa"); sbox.Add("15", "59");
            sbox.Add("16", "47"); sbox.Add("17", "f0"); sbox.Add("18", "ad"); sbox.Add("19", "d4"); sbox.Add("1a", "a2");
            sbox.Add("1b", "af"); sbox.Add("1c", "9c"); sbox.Add("1d", "a4"); sbox.Add("1e", "72"); sbox.Add("1f", "c0");
            sbox.Add("20", "b7"); sbox.Add("21", "fd"); sbox.Add("22", "93"); sbox.Add("23", "26"); sbox.Add("24", "36");
            sbox.Add("25", "3f"); sbox.Add("26", "f7"); sbox.Add("27", "cc"); sbox.Add("28", "34"); sbox.Add("29", "a5");
            sbox.Add("2a", "e5"); sbox.Add("2b", "f1"); sbox.Add("2c", "71"); sbox.Add("2d", "d8"); sbox.Add("2e", "31"); sbox.Add("2f", "15");
            sbox.Add("30", "64"); sbox.Add("31", "c7"); sbox.Add("32", "23"); sbox.Add("33", "c3"); sbox.Add("34", "18"); sbox.Add("35", "96");
            sbox.Add("36", "05"); sbox.Add("37", "9a"); sbox.Add("38", "07"); sbox.Add("39", "12"); sbox.Add("3a", "80");
            sbox.Add("3b", "e2"); sbox.Add("3c", "eb"); sbox.Add("3d", "27"); sbox.Add("3e", "b2"); sbox.Add("3f", "75");
            #endregion
            return cipher;
        }
    }
}
