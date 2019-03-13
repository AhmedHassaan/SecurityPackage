using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        Dictionary<char, KeyValuePair<int, int>> charMap;
        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string decryptedText = "";
            char[,] matrix = fill(key);
            cipherText = cipherText.ToLower();
            cipherText = cipherText.Replace('j', 'i');
            for (int i = 0; i < cipherText.Length; i++)
            {
                string temp;
                temp = "";
                if ((i == cipherText.Length - 1) || (cipherText[i] == cipherText[i + 1]))
                    temp = cipherText[i].ToString() + "x";
                else
                    temp = cipherText[i].ToString() + cipherText[++i].ToString();
                KeyValuePair<int, int> t1 = charMap[temp[0]];
                KeyValuePair<int, int> t2 = charMap[temp[1]];
                if (t1.Key == t2.Key)
                {
                    int intTemp1 = (t1.Value - 1 == -1) ? 4 : t1.Value - 1;
                    int intTemp2 = (t2.Value - 1 == -1) ? 4 : t2.Value - 1;

                    decryptedText += matrix[t1.Key, intTemp1].ToString() + matrix[t2.Key, intTemp2].ToString();
                }
                else if (t1.Value == t2.Value)
                {
                    int intTemp1 = (t1.Key - 1 == -1) ? 4 : t1.Key - 1;
                    int intTemp2 = (t2.Key - 1 == -1) ? 4 : t2.Key - 1;

                    decryptedText += matrix[intTemp1, t1.Value].ToString() + matrix[intTemp2, t2.Value].ToString();
                }
                else
                    decryptedText += matrix[t1.Key, t2.Value].ToString() + matrix[t2.Key, t1.Value].ToString();
            }
            string tempChar = "";
            for(int i=0;i<decryptedText.Length - 2; i += 2)
            {
                tempChar += decryptedText[i].ToString();
                if (!(decryptedText[i] == decryptedText[i + 2] && decryptedText[i + 1] == 'x'))
                    tempChar += decryptedText[i + 1].ToString();
            }
            if (decryptedText[decryptedText.Length - 1] != 'x')
                decryptedText = tempChar + decryptedText[decryptedText.Length - 2].ToString() 
                    + decryptedText[decryptedText.Length - 1].ToString();
            else
                decryptedText = tempChar + decryptedText[decryptedText.Length - 2].ToString();
            return decryptedText;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string encryptedText = "";
            char[,] matrix = fill(key);
            plainText = plainText.Replace('j', 'i');
            for(int i = 0; i < plainText.Length; i++)
            {
                string temp;
                temp = "";
                if ((i == plainText.Length - 1) || (plainText[i] == plainText[i + 1]))
                    temp = plainText[i].ToString() + "x";
                else
                    temp = plainText[i].ToString() + plainText[++i].ToString() + "";
                KeyValuePair<int, int> t1 = charMap[temp[0]];
                KeyValuePair<int, int> t2 = charMap[temp[1]];
                if(t1.Key == t2.Key)
                {
                    int intTemp1 = (t1.Value + 1) % 5;
                    int intTemp2 = (t2.Value + 1) % 5;
                    encryptedText += matrix[t1.Key, intTemp1].ToString() + matrix[t2.Key, intTemp2].ToString();
                }
                else if(t1.Value == t2.Value)
                {
                    int intTemp1 = (t1.Key + 1) % 5;
                    int intTemp2 = (t2.Key + 1) % 5;
                    encryptedText += matrix[intTemp1, t1.Value].ToString() + matrix[intTemp2, t2.Value].ToString();
                }
                else
                    encryptedText += matrix[t1.Key, t2.Value].ToString() + matrix[t2.Key, t1.Value].ToString();
            }
            return encryptedText;
        }
        private char[,] fill(string key)
        {
            List<char> allChars = new List<char>();
            charMap = new Dictionary<char, KeyValuePair<int, int>>();
            for (int i = 0; i < key.Length; i++)
                if (!allChars.Contains(key[i]))
                    allChars.Add(key[i]);
            for (char c = 'a'; c <= 'z'; c++)
                if (!allChars.Contains(c) && c != 'j')
                    allChars.Add(c);
            char[,] temp = new char[5, 5];
            int t = 0;
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                {
                    charMap.Add(allChars[t], new KeyValuePair<int, int>(i, j));
                    temp[i, j] = allChars[t++];
                }
            return temp;
        }
    }
}
