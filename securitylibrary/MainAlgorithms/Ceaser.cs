using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            int c;
            string cipher = "";
            char mychar = 'a';
            for (int i = 0; i < plainText.Length; i++) 
            {
                c = (indexof(plainText[i]) + key)%26;
                for (int j = 0; j < c; j++) 
                    mychar++;
                cipher += mychar;
                mychar = 'a';
            }
            return cipher;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            int c;
            string plaint = "";
            char mychar = 'a';
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++) 
            {
                c = (indexof(cipherText[i]) - key);
                if (c < 0)
                    c = 26 + c;
                for (int j = 0; j < c; j++)
                    mychar++;
                plaint += mychar;
                mychar = 'a';
            }
            return plaint;
            //throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            char z, x;
            string s = cipherText.ToLower();
            z = plainText[0];
            x = s[0];
            int i = 0;
            if (z == x) return 0;
            if (x > z)
                for (char c = z; c < x; c++)
                    i++;
            else
            {
                for (char c = x; c < z; c++)
                    i++;
                return 26 - i;
            }
            return i;
            //throw new NotImplementedException();
        }
        public int indexof(char c) 
        {
            int i = 0;
            for (char cc = 'a'; cc < c; cc++)
                i++;
            return i;
        }
    }
}
