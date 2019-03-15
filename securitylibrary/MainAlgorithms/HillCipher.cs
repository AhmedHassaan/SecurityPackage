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
            int col = (int)(Math.Ceiling(plainText.Count / 2.0));
            int[,] pt = new int[2,col];
            int[,] ct = new int[2,col];
            int count = 0;
            for (int i = 0; i < col; i++)//bros l plaintext
                for (int j = 0; j < 2; j++)
                {
                    pt[j, i] = plainText[count];
                    ct[j, i] = cipherText[count++];
                }
            List<KeyValuePair<int, int>> allPerm = getAllPerm(col);
            List<int> finalAns = new List<int>();
            for (int i = 0; i < allPerm.Count; i++)
            {
                bool inverseFound = false;
                int[,] tempPT = new int[2, 2];
                int[,] tempCT = new int[2, 2];
                tempPT[0, 0] = pt[0, allPerm[i].Key];
                tempPT[1, 0] = pt[1, allPerm[i].Key];
                tempPT[0, 1] = pt[0, allPerm[i].Value];
                tempPT[1, 1] = pt[1, allPerm[i].Value];
                tempCT[0, 0] = ct[0, allPerm[i].Key];
                tempCT[1, 0] = ct[1, allPerm[i].Key];
                tempCT[0, 1] = ct[0, allPerm[i].Value];
                tempCT[1, 1] = ct[1, allPerm[i].Value];
                int b = ((tempPT[0, 0] * tempPT[1, 1]) - (tempPT[1, 0] * tempPT[0, 1])) % 26;
                if (b < 0)
                    b += 26;
                int modInv = 0;
                #region  Extended Euclidean Algorithm
                int[] As = new int[3];
                int[] Bs = new int[3];
                int[] Ts = new int[3];
                As[0] = 1; As[1] = 0; As[2] = 26;
                Bs[0] = 0; Bs[1] = 1; Bs[2] = b;
                while (true)
                {
                    if (Bs[2] == 0)
                    {
                        inverseFound = false;
                        break;
                    }
                    else if(Bs[2] == 1)
                    {
                        inverseFound = true;
                        modInv = Bs[1];
                        break;
                    }
                    int q = As[2] / Bs[2];
                    Ts[0] = As[0] - (q * Bs[0]); Ts[1] = As[1] - (q * Bs[1]); Ts[2] = As[2] - (q * Bs[2]);
                    As[0] = Bs[0]; As[1] = Bs[1]; As[2] = Bs[2];
                    Bs[0] = Ts[0]; Bs[1] = Ts[1]; Bs[2] = Ts[2];
                }
                #endregion
                if (!inverseFound)
                    continue;
                else
                {
                    int[,] tempInvPT = new int[2, 2];
                    tempInvPT[0, 0] = (tempPT[1, 1] * modInv) % 26;
                    if (tempInvPT[0, 0] < 0)
                        tempInvPT[0, 0] += 26;
                    tempInvPT[0, 1] = (-1 * tempPT[0, 1] * modInv) % 26;
                    if (tempInvPT[0, 1] < 0)
                        tempInvPT[0, 1] += 26;
                    tempInvPT[1, 0] = (-1 * tempPT[1, 0] * modInv) % 26;
                    if (tempInvPT[1, 0] < 0)
                        tempInvPT[1, 0] += 26;
                    tempInvPT[1, 1] = (tempPT[0, 0] * modInv) % 26;
                    if (tempInvPT[1, 1] < 0)
                        tempInvPT[1, 1] += 26;
                    int[,] tempKey = new int[2, 2];
                    for (int m = 0; m < 2; m++)
                    {
                        for (int n = 0; n < 2; n++)
                        {
                            tempKey[m, n] = 0;
                            for (int k = 0; k < 2; k++)
                                tempKey[m, n] += tempCT[m, k] * tempInvPT[k, n];
                            tempKey[m, n] %= 26;
                        }
                    }
                    int[,] finalCT = new int[2, col];
                    for (int m = 0; m < 2; m++)
                    {
                        for (int n = 0; n < col; n++)
                        {
                            finalCT[m, n] = 0;
                            for (int k = 0; k < 2; k++)
                                finalCT[m, n] += tempKey[m, k] * pt[k, n];
                            finalCT[m, n] %= 26;
                        }
                    }
                    bool found = true;
                    for (int m = 0; m < 2; m++)
                    {
                        for (int n = 0; n < col; n++)
                            if (finalCT[m, n] != ct[m, n])
                            {
                                found = false;
                                break;
                            }
                        if (!found)
                            break;
                    }
                    if (!found)
                        continue;
                    #region
                    //int min1 = (tempKey[0, 0] < tempKey[0, 1]) ? tempKey[0, 0] : tempKey[0, 1];
                    //int min2 = (tempKey[1, 0] < tempKey[1, 1]) ? tempKey[1, 0] : tempKey[1, 1];
                    //int min = (min1 < min2) ? min1 : min2;
                    //int cf = 1;
                    //for (int m = 1; m <= min; m++)
                    //    if (tempKey[0, 0] % m == 0 && tempKey[0, 1] % m == 0 && tempKey[1, 0] % m == 0 && tempKey[1, 1] % m == 0)
                    //        cf = m;
                    //tempKey[0, 0] /= cf;
                    //tempKey[1, 0] /= cf;
                    //tempKey[0, 1] /= cf;
                    //tempKey[1, 1] /= cf;
                    #endregion
                    finalAns.Add(tempKey[0, 0]); finalAns.Add(tempKey[0, 1]);
                    finalAns.Add(tempKey[1, 0]); finalAns.Add(tempKey[1, 1]);
                    return finalAns;
                }
            }
            throw new InvalidAnlysisException();
        }

        private List<KeyValuePair<int, int>> getAllPerm(int col)
        {
            List<KeyValuePair<int, int>> temp = new List<KeyValuePair<int, int>>();
            for (int i = 0; i < col - 1; i++)
                for (int j = i + 1; j < col; j++)
                    temp.Add(new KeyValuePair<int, int>(i, j));
            return temp;
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
