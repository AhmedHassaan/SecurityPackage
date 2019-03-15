using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            List<List<int>> finalKey = new List<List<int>>();
            List<int> key = new List<int>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            cipherText = cipherText.Replace("\0", "");
            bool finish = false;
            key.Add(1);
            //key.Add(2); key.Add(3); key.Add(4); key.Add(5); key.Add(6);
            for (int i = 2; i < plainText.Length; i++)
            {
                key.Add(i);
                getPermutation(key.ToArray(), 0, key.Count - 1, plainText, cipherText,ref finalKey);
                for(int n = 0; n < finalKey.Count; n++)
                {
                    string t;
                    t = Encrypt(plainText, finalKey[n]);
                    t = t.Replace("\0", "");
                    if (t.Equals(cipherText))
                    {
                        key = finalKey[n];
                        finish = true;
                        break;
                    }
                }
                if (finish)
                    break;
                finalKey.Clear();
            }
            return key;
        }
        public void getPermutation(int[] list, int start, int end, string plainText, string cipherText,ref List<List<int>> finalList)
        {
            if (start == end)
                finalList.Add(list.ToList());
            else {
                for (int i = start; i <= end; i++)
                {
                    int temp = list[start]; list[start] = list[i]; list[i] = temp;
                    getPermutation(list, start + 1, end, plainText, cipherText, ref finalList);
                    temp = list[start]; list[start] = list[i]; list[i] = temp;
                }
            }
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string plain = "";
            int maxCol = key.Count;
            double c = Convert.ToDouble(cipherText.Length) / Convert.ToDouble(maxCol);
            double row = Math.Ceiling(c);
            char[,] matrix = new char[Convert.ToInt32(row), maxCol];
            int count = 0;
            for (int i = 0; i < maxCol; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    try { matrix[j, key.IndexOf(i + 1)] = cipherText[count++]; }
                    catch { break; }
                }
            }
            for (int i = 0; i < row; i++)
                for (int j = 0; j < maxCol; j++)
                    plain += matrix[i, j];
            plain = plain.Replace("\0", "");
            return plain;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            string cipher = "";
            int maxCol = key.Count;
            double c = Convert.ToDouble(plainText.Length) / Convert.ToDouble(maxCol);
            double row = Math.Ceiling(c);
            char[,] matrix = new char[Convert.ToInt32(row), maxCol];
            char[,] matrix2 = new char[Convert.ToInt32(row), maxCol];
            int count = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < maxCol; j++)
                {
                    try { matrix[i, j] = plainText[count++]; }
                    catch { break; }
                }
            }
            for (int i = 0; i < maxCol; i++)
                for (int j = 0; j < row; j++)
                    matrix2[j, key[i] - 1] = matrix[j, i];
            for (int i = 0; i < maxCol; i++)
            {
                for (int j = 0; j < row; j++)
                {
                    try { cipher += matrix2[j, i]; }
                    catch { break; }
                }

            }
            return cipher;
        }
    }
}
