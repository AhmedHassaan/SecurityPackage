using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            List<int> key = new List<int>(4);
            int col = (int)(Math.Ceiling(plainText.Count / 2.0));
            int[,] pt = new int[2, col];
            int[,] ct = new int[2, col];
            int count = 0;
            for (int i = 0; i < 2; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    pt[i, j] = plainText[count];
                    ct[i, j] = cipherText[count++];
                }
            }
            count = 0;
            key.Add(0); key.Add(0); key.Add(0); key.Add(0);
            for (int i = 0; i < col - 1; i++)
            {
                List<double> temp = new List<double>(4);
                temp.Clear();
                double x = 1 / (((double)pt[0, i] * (double)pt[1, i + 1]) - ((double)pt[0, i + 1] * (double)pt[1, i]));
                //temp[0] = x * (double)pt[1, i + 1];
                //temp[1] = x * -1.0 * (double)pt[0, i + 1];
                //temp[2] = x * -1.0 * (double)pt[1, i];
                //temp[3] = x * (double)pt[0, i];
                temp.Add(x * (double)pt[1, i + 1]);
                temp.Add(x * -1.0 * (double)pt[0, i + 1]);
                temp.Add(x * -1.0 * (double)pt[1, i]);
                temp.Add(x * (double)pt[0, i]);
                if (Math.Ceiling(temp[0]) != temp[0] ||
                    Math.Ceiling(temp[1]) != temp[1] ||
                    Math.Ceiling(temp[2]) != temp[2] ||
                    Math.Ceiling(temp[3]) != temp[3])
                    continue;
                for(int j = 0; j < col - 1; j++)
                {
                    key[0] = (((int)temp[0] * ct[0, j]) + ((int)temp[1] * ct[1, j])) % 26;
                    key[1] = (((int)temp[0] * ct[0, j + 1]) + ((int)temp[1] * ct[1, j + 1])) % 26;
                    key[2] = (((int)temp[2] * ct[0, j]) + ((int)temp[3] * ct[1, j])) % 26;
                    key[3] = (((int)temp[2] * ct[0, j + 1]) + ((int)temp[3] * ct[1, j + 1])) % 26;
                    List<int> temp2 = Encrypt(plainText, key);
                    if (temp.Equals(cipherText))
                    {
                        return key;
                    }
                }


            }


            //count = 0;
            //for(int j = 0; j < col - 1; j++)
            //{
            //    for (int i = 0; i < col - 1; i++)
            //    {
            //        key[0] = ((pt[0, j] * ct[0, i]) + (pt[0, j + 1] * ct[1, i]))%26;
            //        key[1] = ((pt[0, j] * ct[0, i + 1]) + (pt[0, j + 1] * ct[1, i + 1]))% 26;
            //        key[2] = ((pt[1, j] * ct[0, i]) + (pt[1, j + 1] * ct[1, i]))% 26;
            //        key[3] = ((pt[1, j] * ct[0, i + 1]) + (pt[1, j + 1] * ct[1, i + 1]))% 26;
            //        List<int> temp = Encrypt(plainText, key);
            //        if (temp.Equals(cipherText))
            //        {
            //            return key;
            //        }
            //    }
            //}

            throw new InvalidAnlysisException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int> plainText = new List<int>();

            int h = 0;

            switch (key.Count)
            {
                case 4:
                    h = 2;
                    break;
                case 9:
                    h = 3;
                    break;
            }
            for (int i = 0; i < key.Count; i++)
            {
                if (key[i] < 0) throw new InvalidAnlysisException();

            }





            int detK = 0;
            int[,] keyM = new int[h, h];


            int key_ctr = 0;

            //dy keda by3ml l key


            if (h == 2)
            {
                List<double> keyInv = new List<double>(4);


                double x = 1 / ((double)key[0] * (double)key[3] - (double)key[1] * (double)key[2]);

                for (int i = 0; i < 4; i++)
                {
                    if (i == 0)
                        keyInv.Add((key[3] * x));
                    else if (i == 3)
                        keyInv.Add((key[0] * x));
                    else
                        keyInv.Add((-key[i] * x));

                    if (key[i] < 26) key[i] += 26;

                }
                List<int> fixedKeyInv = new List<int>(4);
                for (int i = 0; i < keyInv.Count; i++)
                {
                    if (Math.Ceiling(keyInv[i]) != keyInv[i]) throw new InvalidAnlysisException();
                    fixedKeyInv.Add((int)keyInv[i]);
                }

                
                return Encrypt(cipherText, fixedKeyInv);

            }

            else
            {
                for (int i = 0; i < h; i++)
                {
                    for (int j = 0; j < h; j++)
                    {
                        keyM[i, j] = key[key_ctr];
                        key_ctr++;
                    }
                }// bt3ml matrix l key

                for (int i = 0; i < h; i++)
                {
                    switch (i)
                    {
                        case 0:
                            detK += keyM[0, i] * (keyM[1, 1] * keyM[2, 2] - keyM[2, 1] * keyM[1, 2]);
                            break;
                        case 1:
                            detK -= keyM[0, i] * (keyM[1, 0] * keyM[2, 2] - keyM[2, 0] * keyM[1, 2]);
                            break;
                        case 2:
                            detK += keyM[0, i] * (keyM[1, 0] * keyM[2, 1] - keyM[2, 0] * keyM[1, 1]);
                            break;
                    }
                }
            }

            detK %= 26;
            if (detK < 0)
                detK += 26;

            double denominator = 26 - detK;
            double numerator = 1;
            int b;
            int c;

            while (true)
            {
                if ((numerator / denominator) % 1 == 0)
                {
                    c = (int)(numerator / denominator);
                    break;
                }
                numerator += 26;
            }
            b = 26 - c;

            List<List<int>> allDets = new List<List<int>>(h * h);

            for (int i = 0; i < h; i++) // calculating determinand 
            {
                for (int j = 0; j < h; j++)
                {
                    List<int> dets = new List<int>(4);
                    for (int m = 0; m < h; m++)
                    {
                        for (int n = 0; n < h; n++)
                        {

                            if (m == i || n == j)
                                continue;
                            dets.Add(keyM[m, n]);

                        }
                    }
                    allDets.Add(dets);
                }
            }

            List<int> detVals = new List<int>(h * h);


            foreach (var l in allDets) // getting D values
            {
                int res = l.ElementAt(0) * l.ElementAt(3) - l.ElementAt(1) * l.ElementAt(2);
                detVals.Add(res);
            }

            for (int i = 0; i < h; i++) // 3rd step applying general rule
            {
                for (int j = 0; j < h; j++)
                {
                    int res = (b * (int)Math.Pow(-1, (i + j)) * detVals.ElementAt(0)) % 26;

                    if (res < 0) res += 26;
                    keyM[i, j] = res;
                    detVals.RemoveAt(0);
                }
            }

            int[,] tranposeM = new int[h, h];

            List<int> transpose = new List<int>(9);

            for (int i = 0; i < h; i++)
            {
                for (int j = 0; j < h; j++)
                {
                    tranposeM[j, i] = keyM[i, j];
                }
            }

            for (int i = 0; i < h; i++)
            {
                for (int j = 0; j < h; j++)
                {
                    transpose.Add(tranposeM[i, j]);
                }
            }


            return Encrypt(cipherText, transpose);
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();

            List<int> cypherTxt = new List<int>();

            //check key validation


            if (key.Count == 9 || key.Count == 4)
            {


                int h = 0;

                switch (key.Count)
                {
                    case 4:
                        h = 2;
                        break;
                    case 9:
                        h = 3;
                        break;

                }



                float txtSize = plainText.Count;
                float x = txtSize / h;
                int w = (int)Math.Ceiling(x);

                while (plainText.Count < h * w)
                {
                    plainText.Add(23);// bzwd x's 
                }

                int[,] keyM = new int[h, h];
                int[,] pTextM = new int[h, w];

                int key_ctr = 0;

                for (int i = 0; i < h; i++)//bros l key
                {
                    for (int j = 0; j < h; j++)
                    {
                        keyM[i, j] = key[key_ctr];
                        key_ctr++;
                    }
                }

                for (int i = 0; i < h; i++)//bros l plaintext
                {
                    for (int j = 0, k = 0; j < w; j++, k += h)
                    {
                        if (j == 0)
                            pTextM[i, j] = plainText[i];
                        else
                        {
                            pTextM[i, j] = plainText[i + k];
                        }
                    }
                }

                for (int k = 0; k < w; k++)//bt3t el txt matrix btmshy l7ad l w bta3 l matix
                {

                    for (int i = 0; i < h; i++)
                    {
                        int value = 0;
                        for (int j = 0; j < h; j++)
                        {
                            value += keyM[i, j] * pTextM[j, k];
                            value %= 26;
                            if (value < 0) value += 26;


                        }
                        cypherTxt.Add(value);
                    }

                }

            }
            else
            {
                throw new InvalidAnlysisException();
            }








            return cypherTxt;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();


            int h = 3;
            int detK = 0;

            int[,] plainM = new int[h, h];
            int[,] cypherM = new int[h, h];

            for (int i = 0; i < h; i++)//bros l plaintext (key)
            {
                for (int j = 0, k = 0; j < 3; j++, k += h)
                {
                    if (j == 0)
                        plainM[i, j] = plainText[i];
                    else
                    {
                        plainM[i, j] = plainText[i + k];
                    }
                }
            }



            for (int i = 0; i < 3; i++)// bros el cipher
            {
                for (int j = 0, k = 0; j < 3; j++, k += h)
                {
                    if (j == 0)
                        cypherM[i, j] = cipherText[i];
                    else
                    {
                        cypherM[i, j] = cipherText[i + k];
                    }
                }
            }



            for (int i = 0; i < h; i++)
            {
                switch (i)
                {
                    case 0:
                        detK += plainM[0, i] * (plainM[1, 1] * plainM[2, 2] - plainM[2, 1] * plainM[1, 2]);
                        break;
                    case 1:
                        detK -= plainM[0, i] * (plainM[1, 0] * plainM[2, 2] - plainM[2, 0] * plainM[1, 2]);
                        break;
                    case 2:
                        detK += plainM[0, i] * (plainM[1, 0] * plainM[2, 1] - plainM[2, 0] * plainM[1, 1]);
                        break;
                }
            }


            detK %= 26;
            if (detK < 0)
                detK += 26;

            double denominator = 26 - detK;
            double numerator = 1;
            int b;
            int c;

            while (true)
            {
                if ((numerator / denominator) % 1 == 0)
                {
                    c = (int)(numerator / denominator);
                    break;
                }
                numerator += 26;
            }
            b = 26 - c;

            List<List<int>> allDets = new List<List<int>>(h * h);

            for (int i = 0; i < h; i++) // calculating determinand 
            {
                for (int j = 0; j < h; j++)
                {
                    List<int> dets = new List<int>(4);
                    for (int m = 0; m < h; m++)
                    {
                        for (int n = 0; n < h; n++)
                        {

                            if (m == i || n == j)
                                continue;
                            dets.Add(plainM[m, n]);

                        }
                    }
                    allDets.Add(dets);
                }
            }

            List<int> detVals = new List<int>(h * h);


            foreach (var l in allDets) // getting D values
            {
                int res = l.ElementAt(0) * l.ElementAt(3) - l.ElementAt(1) * l.ElementAt(2);
                detVals.Add(res);
            }

            for (int i = 0; i < h; i++) // 3rd step applying general rule
            {
                for (int j = 0; j < h; j++)
                {
                    int res = (b * (int)Math.Pow(-1, (i + j)) * detVals.ElementAt(0)) % 26;

                    if (res < 0) res += 26;
                    plainM[i, j] = res;
                    detVals.RemoveAt(0);
                }
            }

            int[,] tranposeM = new int[h, h];

            List<int> transpose = new List<int>(9);

            for (int i = 0; i < h; i++)
            {
                for (int j = 0; j < h; j++)
                {
                    tranposeM[j, i] = plainM[i, j];
                }
            }


            for (int i = 0; i < h; i++)
            {
                for (int j = 0; j < h; j++)
                {
                    transpose.Add(tranposeM[i, j]);
                }
            }





            int[,] arr = new int[3, 3];

            List<int> key = new List<int>();

            for (int k = 0; k < 3; k++)//bdrbhom f b3d
            {

                for (int i = 0; i < h; i++)
                {
                    int value = 0;
                    for (int j = 0; j < h; j++)
                    {
                        value += cypherM[i, j] * tranposeM[j, k];
                        value %= 26;
                        if (value < 0) value += 26;

                    }
                    key.Add(value);
                }
            }





            for (int i = 0; i < 3; i++)// bros el cipher
            {
                for (int j = 0, k = 0; j < 3; j++, k += h)
                {
                    if (j == 0)
                        arr[i, j] = key[i];
                    else
                    {
                        arr[i, j] = key[i + k];
                    }
                }
            }

            key.Clear();

            for (int i = 0; i < 3; i++)// bros el cipher
            {
                for (int j = 0; j < 3; j++)
                {
                    key.Add(arr[i, j]);

                }
            }

            return key;


        }

    }
}
