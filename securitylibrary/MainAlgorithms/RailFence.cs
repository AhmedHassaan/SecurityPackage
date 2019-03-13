using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int key = 0;
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for(int i = 2; i < plainText.Length; i++)
            {
                string temp = Encrypt(plainText, i).ToLower();
                temp = temp.Replace("\0", "");
                if (temp.Equals(cipherText))
                {
                    key = i;
                    break;
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            double c = Convert.ToDouble(cipherText.Length) / Convert.ToDouble(key);
            double col = Math.Ceiling(c);
            int count = 0;
            string plain = "";
            char[,] mat = new char[key, Convert.ToInt32(col)];
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    try
                    {
                        mat[i, j] = cipherText[count];
                        count++;
                    }
                    catch { break; }
                }
            }
            for (int i = 0; i < col; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    try
                    {
                        plain += mat[j, i];
                    }
                    catch { break; }
                }
            }
            return plain;
           // throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            double c = Convert.ToDouble(plainText.Length) / Convert.ToDouble(key);
            double col = Math.Ceiling(c);
            int count = 0;
            string cipher = "";
            char[,] mat = new char[key, Convert.ToInt32(col)];
            for (int i = 0; i < col; i++) 
            {
                for (int j = 0; j < key; j++) 
                {
                    try
                    {
                        mat[j, i] = plainText[count];
                        count++;
                    }
                    catch { break; }
                }
            }
            for (int i = 0; i < key; i++) 
            {
                for (int j = 0; j < col; j++) 
                {
                    try
                    {
                        cipher += mat[i, j];
                    }
                    catch { break; }
                }
            }
            return cipher.ToUpper() ;
            //throw new NotImplementedException();
        }
    }
}
