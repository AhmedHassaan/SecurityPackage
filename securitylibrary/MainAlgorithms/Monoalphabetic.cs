using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            var map = new Dictionary<char ,char>();
            for (int i = 0; i < cipherText.Length;i++)
            {
                if (!map.ContainsKey(plainText[i]))
                    map.Add(plainText[i], cipherText[i]);
            }
            char c = 'a';
            string key = "";
            for (int i = 0; i < 26; i++)
            {
                if (map.ContainsKey(c))
                    key += map[c];
                else
                    key += '.';
                c++;
            }
            string s = "";
            c = 'a';
            for (int i = 0; i < 26; i++) 
            {
                if (key[i] == '.')
                {
                    while (true) 
                    {
                        if (cipherText.ToLower().Contains(c))
                            c++;
                        else
                        {
                            s += c;
                            c++;
                            break;
                        }
                    }
                }
                
            }
            string final = "";
            int q = 0;
            for (int i = 0; i < 26; i++) 
            {
                if (key[i] != '.')
                    final += key[i];
                else{
                    final += s[q];
                    q++;
                }
            }
            
                return final.ToLower();
           
        }

        public string Decrypt(string cipherText, string key)
        {
            string plaint = "";
            char c = 'a';
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++) 
            {
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == key[j])
                        for (int q = 0; q < j; q++)
                            c++;
                }
                plaint += c;
                c = 'a';
            }
            return plaint;
            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            char c = 'a';
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (plainText[i] == c)
                    {
                        cipher += key[j];
                        break;
                    }
                    c++;
                }
                c = 'a';
            }
            return cipher;
            //throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            String plain = "";
            cipher = cipher.ToLower();

            //Dictionary<char, float> freqInformation = new Dictionary<char, float>();
            //freqInformation.Add('e', 12.51f); freqInformation.Add('t', 9.25f); freqInformation.Add('a', 8.04f); freqInformation.Add('o', 7.60f);
            //freqInformation.Add('i', 7.26f); freqInformation.Add('n', 7.09f); freqInformation.Add('s', 6.54f); freqInformation.Add('r', 6.12f);
            //freqInformation.Add('h', 5.49f); freqInformation.Add('l', 4.14f); freqInformation.Add('d', 3.99f); freqInformation.Add('c', 3.06f);
            //freqInformation.Add('u', 2.17f); freqInformation.Add('m', 2.53f); freqInformation.Add('f', 2.30f); freqInformation.Add('p', 2.00f);
            //freqInformation.Add('g', 1.96f); freqInformation.Add('w', 1.92f); freqInformation.Add('y', 1.73f); freqInformation.Add('b', 1.54f);
            //freqInformation.Add('v', 0.99f); freqInformation.Add('k', 0.67f); freqInformation.Add('x', 0.19f); freqInformation.Add('j', 0.16f);
            //freqInformation.Add('q', 0.11f); freqInformation.Add('z', 0.09f);

            List<char> freq = new List<char>();
            freq.Add('e'); freq.Add('t'); freq.Add('a'); freq.Add('o');
            freq.Add('i'); freq.Add('n'); freq.Add('s'); freq.Add('r');
            freq.Add('h'); freq.Add('l'); freq.Add('d'); freq.Add('c');
            freq.Add('u'); freq.Add('m'); freq.Add('f'); freq.Add('p');
            freq.Add('g'); freq.Add('w'); freq.Add('y'); freq.Add('b');
            freq.Add('v'); freq.Add('k'); freq.Add('x'); freq.Add('j');
            freq.Add('q'); freq.Add('z');
            Dictionary<char, int> cipherFreq = new Dictionary<char, int>();
            List<Char> charInCipher = new List<char>();
            for (int i = 0; i < cipher.Length; i++)
            {

                if (!cipherFreq.ContainsKey(cipher[i]))
                {
                    cipherFreq.Add(cipher[i], 1);
                    charInCipher.Add(cipher[i]);
                }
                else
                    cipherFreq[cipher[i]] = cipherFreq[cipher[i]] + 1;
            }


            for(int i = 0; i < charInCipher.Count; i++)
            {
                for(int j=0;j<charInCipher.Count - i - 1; j++)
                {
                    if(cipherFreq[charInCipher[j]] < cipherFreq[charInCipher[j + 1]])
                    {
                        char temp = charInCipher[j];
                        charInCipher[j] = charInCipher[j + 1];
                        charInCipher[j + 1] = temp;
                    }
                }
            }

            Dictionary<char, char> mappedChars = new Dictionary<char, char>();
            for (int i = 0; i < charInCipher.Count; i++)
                mappedChars.Add(charInCipher[i], freq[i]);

            for(int i = 0; i < cipher.Length; i++)
            {
                plain += mappedChars[cipher[i]].ToString();
            }


            return plain;
            //throw new NotImplementedException();
        }
    }
}
