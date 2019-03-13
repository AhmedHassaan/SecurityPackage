using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string key = "";
            char[,] matrix = buildMatrix();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                int col = plainText[i] - 'a';
                int row = 0;
                for (int j = 0; j < 26; j++)
                    if (matrix[j, col] == cipherText[i])
                        row = j;
                key += (char)('a' + row);
                string temp = Encrypt(plainText, key);
                if (temp.Equals(cipherText))
                    break;
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            string plain = "";
            char[,] matrix = buildMatrix();
            string oldKey = key;
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (i >= oldKey.Length)
                    key += plain[i - oldKey.Length];
                int row = key[i] - 'a';
                int col = 0;
                for (int j = 0; j < 26; j++)
                    if (matrix[row, j] == cipherText[i])
                        col = j;
                plain += (char)('a' + col);
            }
            return plain;

        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            string cipher = "";
            char[,] matrix = buildMatrix();
            string oldKey = key;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (i >= oldKey.Length)
                    key += plainText[i-oldKey.Length];
                int row = key[i] - 'a';
                int col = plainText[i] - 'a';
                cipher += matrix[row, col];
            }
            return cipher;
        }

        private char[,] buildMatrix()
        {
            char[,] matrix = new char[26, 26];
            char temp = 'a';
            for (int i = 0; i < 26; i++)
            {
                char temp2 = temp;
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = temp;
                    if (temp == 'z')
                        temp = 'a';
                    else
                        temp++;
                }

                if (temp2 == 'z')
                    temp = 'a';
                else
                    temp = ++temp2;
            }

            return matrix;
        }
    }
}
