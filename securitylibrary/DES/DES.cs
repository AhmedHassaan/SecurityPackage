using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.Remove(0, 2);
            while (key.Length < 16)
                key += "0";
            cipherText = cipherText.Remove(0, 2);
            #region generating the bitArray
            byte[] keyTemp = StringToByteArray(key);
            byte[] cipherTextTemp = StringToByteArray(cipherText);
            BitArray cipherTextBits = new BitArray(cipherTextTemp);
            BitArray keyWith64Bit = new BitArray(keyTemp);
            cipherTextBits = swapBitArray(cipherTextBits);
            keyWith64Bit = swapBitArray(keyWith64Bit);
            List<BitArray> keys = new List<BitArray>();
            #endregion

            #region Key Generator //Checked\\
            #region 1- Using PC 1 (Convert from matrix 64 to matrix 56) --Key-- //Checked right answer\\
            int[] pc1 = {   57, 49, 41, 33, 25, 17, 9,
                            1, 58, 50, 42, 34, 26, 18,
                            10, 2, 59, 51, 43, 35, 27,
                            19, 11, 3, 60, 52, 44, 36,
                            63, 55, 47, 39, 31, 23, 15,
                            7, 62, 54, 46, 38, 30, 22,
                            14, 6, 61, 53, 45, 37, 29,
                            21, 13, 5, 28, 20, 12, 4 };
            BitArray keyWith56Bit = new BitArray(pc1.Length);   // from 0 to 27 (Right) -- from 28 to 55 (Left)
            for (int i = 0; i < pc1.Length; i++)
                keyWith56Bit[i] = keyWith64Bit[pc1[i] - 1];

            #endregion

            for (int round = 0; round < 16; round++)
            {
                BitArray keyWith48Bit = new BitArray(48);
                #region 2- Shift the key --Key--
                int[] scheduleOfShiftLeft = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }; // schedule of shifting
                int shiftAmount = scheduleOfShiftLeft[round];
                BitArray shiftedBitsLeft, shiftedBitsRight;
                shiftedBitsLeft = new BitArray(shiftAmount);
                shiftedBitsRight = new BitArray(shiftAmount);
                for (int i = 0; i < shiftAmount; i++)
                {
                    shiftedBitsLeft[i] = keyWith56Bit[i];
                    shiftedBitsRight[i] = keyWith56Bit[28 + i];
                }
                for (int i = shiftAmount; i < 28; i++)
                {
                    // rotate left part
                    keyWith56Bit[i - shiftAmount] = keyWith56Bit[i];
                    // rotate right part
                    keyWith56Bit[28 + i - shiftAmount] = keyWith56Bit[28 + i];
                }
                for (int i = 0; i < shiftAmount; i++)
                {
                    keyWith56Bit[27 - i] = shiftedBitsLeft[shiftAmount - i - 1];
                    keyWith56Bit[55 - i] = shiftedBitsRight[shiftAmount - i - 1];
                }
                #endregion

                #region 3- Using PC 2 (Convert from matrix 56 to matrix 48) --Key--
                int[] pc2 = {  14, 17, 11, 24, 1, 5,
                                3, 28, 15, 6, 21, 10,
                                23, 19, 12, 4, 26, 8,
                                16, 7, 27, 20, 13, 2,
                                41, 52, 31, 37, 47, 55,
                                30, 40, 51, 45, 33, 48,
                                44, 49, 39, 56, 34, 53,
                                46, 42, 50, 36, 29, 32 };
                keyWith48Bit = new BitArray(pc2.Length);
                for (int i = 0; i < pc2.Length; i++)
                    keyWith48Bit[i] = keyWith56Bit[pc2[i] - 1];
                #endregion
                keys.Add(keyWith48Bit);
            }
            for (int i = 0; i < 8; i++)
            {
                BitArray bb = keys[i];
                keys[i] = keys[keys.Count - i - 1];
                keys[keys.Count - i - 1] = bb;
            }
            #endregion


            #region Decryption


            #region 1- Using IP --Message-- (from 0 to 31 (Left) -- from 32 to 63 (Right))
            int[] ip = {58,50,42,34,26,18,10,2,
                        60,52,44,36,28,20,12,4,
                        62,54,46,38,30,22,14,6,
                        64,56,48,40,32,24,16,8,
                        57,49,41,33,25,17,9,1,
                        59,51,43,35,27,19,11,3,
                        61,53,45,37,29,21,13,5,
                        63,55,47,39,31,23,15,7};
            BitArray cipherWith64Bit = new BitArray(ip.Length);   // from 0 to 31 (Left) -- from 32 to 63 (Right)
            for (int i = 0; i < ip.Length; i++)
                cipherWith64Bit[i] = cipherTextBits[ip[i] - 1];
            #endregion
            for (int round = 0; round < 16; round++)
            {
                #region 2- Using EP (Convert from matrix 32 (right part of the cipher) to matrix 48) --Message-- //Checked\\
                int[] expansionFunction = {32,1,2,3,4,5,
                                            4,5,6,7,8,9,
                                           8,9,10,11,12,13,
                                          12,13,14,15,16,17,
                                          16,17,18,19,20,21,
                                          20,21,22,23,24,25,
                                          24,25,26,27,28,29,
                                          28,29,30,31,32,1};
                BitArray cipherWith48Bit = new BitArray(expansionFunction.Length);
                for (int i = 0; i < expansionFunction.Length; i++)
                    cipherWith48Bit[i] = cipherWith64Bit[expansionFunction[i] - 1 + 32];
                #endregion
                #region 3- cipherWith48Bit XOR keyWith48Bit --Message-- //Checked\\
                BitArray cipherXORkey = cipherWith48Bit.Xor(keys[round]);
                #endregion
                #region 4- S-Box (Bnsht8l 3la aly tal3 mn al xor) --Message-- //Checked\\
                //num = new BitArray(BitConverter.GetBytes(13));
                int[,] sbox = new int[8, 64] { {     14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
                                                0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
                                                4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
                                                15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 },
                                              { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
                                                3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
                                                0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
                                                13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 },
                                              { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
                                                13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
                                                13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
                                                1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 },
                                              { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
                                                13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
                                                10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
                                                3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 },
                                              { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
                                                14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
                                                4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
                                                11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 },
                                              { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
                                                10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
                                                9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
                                                4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 },
                                              { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
                                                13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
                                                1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
                                                6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 },
                                              { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
                                                1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
                                                7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
                                                2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 } };
                BitArray sboxResult = new BitArray(32);
                for (int i = 0; i < 8; i++)
                {
                    BitArray row = new BitArray(2);
                    BitArray col = new BitArray(4);
                    row[1] = cipherXORkey[(i * 6)];
                    row[0] = cipherXORkey[(i * 6) + 5];

                    col[0] = cipherXORkey[(i * 6) + 4];
                    col[1] = cipherXORkey[(i * 6) + 3];
                    col[2] = cipherXORkey[(i * 6) + 2];
                    col[3] = cipherXORkey[(i * 6) + 1];

                    int[] arrRow = new int[1];
                    row.CopyTo(arrRow, 0);
                    int[] arrCol = new int[1];
                    col.CopyTo(arrCol, 0);

                    int value = sbox[i, (arrRow[0] * 16) + arrCol[0]];
                    BitArray bitValue = getBitArray4BitFromInt(value);
                    for (int k = 0; k < 4; k++)
                        sboxResult[(i * 4) + k] = bitValue[k];
                }
                //BitArray a = new BitArray(4); a[0] = false; a[1] = false; a[2] = false; a[3] = true;
                //int z = getIntFromBitArray(a);
                //BitArray aa = getBitArray4BitFromInt(z);
                #endregion
                #region 5- Permutation --Message-- //Checked\\
                int[] permutationMatrix = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                                        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
                BitArray matrixAfterPermutation = new BitArray(permutationMatrix.Length);
                for (int i = 0; i < permutationMatrix.Length; i++)
                    matrixAfterPermutation[i] = sboxResult[permutationMatrix[i] - 1];
                #endregion
                #region 6- permutation matrix (right part) XOR Left part --Message-- //Checked\\
                BitArray leftPart = new BitArray(32);
                for (int i = 0; i < 32; i++)
                    leftPart[i] = cipherWith64Bit[i];
                BitArray rightXORleft = leftPart.Xor(matrixAfterPermutation);
                #endregion
                #region 7- Build the new matrix --Message-- //Checked\\
                BitArray newMatrix = new BitArray(64);
                for (int i = 0; i < 64; i++)
                {
                    if (i > 31)
                        newMatrix[i] = rightXORleft[i - 32];
                    else
                        newMatrix[i] = cipherWith64Bit[i + 32];
                }
                #endregion
                cipherWith64Bit = newMatrix;

            }
            #endregion
            #region 32bit Swap //Checked\\
            for (int i = 0; i < 32; i++)
            {
                bool tempBool = cipherWith64Bit[i];
                cipherWith64Bit[i] = cipherWith64Bit[i + 32];
                cipherWith64Bit[i + 32] = tempBool;
            }
            #endregion
            #region inverseIP //Checked\\
            int[] ipInverse = {40,8,48,16,56,24,64,32,
                                39,7,47,15,55,23,63,31,
                                38,6,46,14,54,22,62,30,
                                37,5,45,13,53,21,61,29,
                                36,4,44,12,52,20,60,28,
                                35,3,43,11,51,19,59,27,
                                34,2,42,10,50,18,58,26,
                                33,1,41,9,49,17,57,25};
            BitArray finalMatrix = new BitArray(64);
            for (int i = 0; i < 64; i++)
                finalMatrix[i] = cipherWith64Bit[ipInverse[i] - 1];
            #endregion
            BitArray tempNew = new BitArray(4);
            StringBuilder result = new StringBuilder(18);
            result.Append("0x");
            for (int i = 0; i < 16; i++)
            {
                tempNew[0] = finalMatrix[(i * 4) + 3];
                tempNew[1] = finalMatrix[(i * 4) + 2];
                tempNew[2] = finalMatrix[(i * 4) + 1];
                tempNew[3] = finalMatrix[(i * 4) + 0];
                byte[] tempByte = new byte[1];
                tempNew.CopyTo(tempByte, 0);
                result.AppendFormat("{0:x1}", tempByte[0]);
            }

            return result.ToString();
        }

        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            key = key.Remove(0, 2);
            plainText = plainText.Remove(0, 2);
            while (key.Length < 16)
                key += "0";
            #region generating the bitArray
            byte[] keyTemp = StringToByteArray(key);
            byte[] plainTextTemp = StringToByteArray(plainText);
            BitArray plainTextBits = new BitArray(plainTextTemp);
            BitArray keyWith64Bit = new BitArray(keyTemp);
            plainTextBits = swapBitArray(plainTextBits);
            keyWith64Bit = swapBitArray(keyWith64Bit);
            List<BitArray> keys = new List<BitArray>();
            #endregion

            #region Key Generator //Checked\\
            #region 1- Using PC 1 (Convert from matrix 64 to matrix 56) --Key-- //Checked right answer\\
            int[] pc1 = {   57, 49, 41, 33, 25, 17, 9,
                            1, 58, 50, 42, 34, 26, 18,
                            10, 2, 59, 51, 43, 35, 27,
                            19, 11, 3, 60, 52, 44, 36,
                            63, 55, 47, 39, 31, 23, 15,
                            7, 62, 54, 46, 38, 30, 22,
                            14, 6, 61, 53, 45, 37, 29,
                            21, 13, 5, 28, 20, 12, 4 };
            BitArray keyWith56Bit = new BitArray(pc1.Length);   // from 0 to 27 (Right) -- from 28 to 55 (Left)
            for (int i = 0; i < pc1.Length; i++)
                keyWith56Bit[i] = keyWith64Bit[pc1[i] - 1];
            #endregion
            
            for (int round = 0; round < 16; round++)
            {
                BitArray keyWith48Bit = new BitArray(48);
                #region 2- Shift the key --Key--
                int[] scheduleOfShiftLeft = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }; // schedule of shifting
                int shiftAmount = scheduleOfShiftLeft[round];
                BitArray shiftedBitsLeft, shiftedBitsRight;
                shiftedBitsLeft = new BitArray(shiftAmount);
                shiftedBitsRight = new BitArray(shiftAmount);
                for (int i = 0; i < shiftAmount; i++)
                {
                    shiftedBitsLeft[i] = keyWith56Bit[i];
                    shiftedBitsRight[i] = keyWith56Bit[28 + i];
                }
                for (int i = shiftAmount; i < 28; i++)
                {
                    // rotate left part
                    keyWith56Bit[i - shiftAmount] = keyWith56Bit[i];
                    // rotate right part
                    keyWith56Bit[28 + i - shiftAmount] = keyWith56Bit[28 + i];
                }
                for (int i = 0; i < shiftAmount; i++)
                {
                    keyWith56Bit[27 - i] = shiftedBitsLeft[shiftAmount - i - 1];
                    keyWith56Bit[55 - i] = shiftedBitsRight[shiftAmount - i - 1];
                }
                #endregion

                #region 3- Using PC 2 (Convert from matrix 56 to matrix 48) --Key--
                int[] pc2 = {  14, 17, 11, 24, 1, 5,
                                3, 28, 15, 6, 21, 10,
                                23, 19, 12, 4, 26, 8,
                                16, 7, 27, 20, 13, 2,
                                41, 52, 31, 37, 47, 55,
                                30, 40, 51, 45, 33, 48,
                                44, 49, 39, 56, 34, 53,
                                46, 42, 50, 36, 29, 32 };
                keyWith48Bit = new BitArray(pc2.Length);
                for (int i = 0; i < pc2.Length; i++)
                    keyWith48Bit[i] = keyWith56Bit[pc2[i] - 1];
                #endregion
                keys.Add(keyWith48Bit);
            }
            #endregion

            #region Encryption


            #region 1- Using IP --Message--
            int[] ip = {58,50,42,34,26,18,10,2,
                        60,52,44,36,28,20,12,4,
                        62,54,46,38,30,22,14,6,
                        64,56,48,40,32,24,16,8,
                        57,49,41,33,25,17,9,1,
                        59,51,43,35,27,19,11,3,
                        61,53,45,37,29,21,13,5,
                        63,55,47,39,31,23,15,7};
            BitArray plainWith64Bit = new BitArray(ip.Length);   // from 0 to 31 (Left) -- from 32 to 63 (Right)
            for (int i = 0; i < ip.Length; i++)
                plainWith64Bit[i] = plainTextBits[ip[i] - 1];
            #endregion
            for (int round = 0; round < 16; round++)
            {
                #region 2- Using EP (Convert from matrix 32 (right part of the plain) to matrix 48) --Message-- //Checked\\
                int[] expansionFunction = {32,1,2,3,4,5,
                                            4,5,6,7,8,9,
                                           8,9,10,11,12,13,
                                          12,13,14,15,16,17,
                                          16,17,18,19,20,21,
                                          20,21,22,23,24,25,
                                          24,25,26,27,28,29,
                                          28,29,30,31,32,1};
                BitArray plainWith48Bit = new BitArray(expansionFunction.Length);
                for (int i = 0; i < expansionFunction.Length; i++)
                    plainWith48Bit[i] = plainWith64Bit[expansionFunction[i] - 1 + 32];
                #endregion
                #region 3- PlainWith48Bit XOR keyWith48Bit --Message-- //Checked\\
                BitArray plainXORkey = plainWith48Bit.Xor(keys[round]);
                #endregion
                #region 4- S-Box (Bnsht8l 3la aly tal3 mn al xor) --Message-- //Checked\\
                //num = new BitArray(BitConverter.GetBytes(13));
                int[,] sbox = new int[8, 64] { {     14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
                                                0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
                                                4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
                                                15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 },
                                              { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
                                                3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
                                                0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
                                                13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 },
                                              { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
                                                13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
                                                13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
                                                1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 },
                                              { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
                                                13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
                                                10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
                                                3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 },
                                              { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
                                                14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
                                                4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
                                                11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 },
                                              { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
                                                10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
                                                9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
                                                4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 },
                                              { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
                                                13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
                                                1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
                                                6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 },
                                              { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
                                                1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
                                                7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
                                                2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 } };
                BitArray sboxResult = new BitArray(32);
                for (int i = 0; i < 8; i++)
                {
                    BitArray row = new BitArray(2);
                    BitArray col = new BitArray(4);
                    row[1] = plainXORkey[(i * 6)];
                    row[0] = plainXORkey[(i * 6) + 5];

                    col[0] = plainXORkey[(i * 6) + 4];
                    col[1] = plainXORkey[(i * 6) + 3];
                    col[2] = plainXORkey[(i * 6) + 2];
                    col[3] = plainXORkey[(i * 6) + 1];

                    int[] arrRow = new int[1];
                    row.CopyTo(arrRow, 0);
                    int[] arrCol = new int[1];
                    col.CopyTo(arrCol, 0);

                    int value = sbox[i, (arrRow[0] * 16) + arrCol[0]];
                    BitArray bitValue = getBitArray4BitFromInt(value);
                    for (int k = 0; k < 4; k++)
                        sboxResult[(i * 4) + k] = bitValue[k];
                }
                //BitArray a = new BitArray(4); a[0] = false; a[1] = false; a[2] = false; a[3] = true;
                //int z = getIntFromBitArray(a);
                //BitArray aa = getBitArray4BitFromInt(z);
                #endregion
                #region 5- Permutation --Message-- //Checked\\
                int[] permutationMatrix = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                                        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
                BitArray matrixAfterPermutation = new BitArray(permutationMatrix.Length);
                for (int i = 0; i < permutationMatrix.Length; i++)
                    matrixAfterPermutation[i] = sboxResult[permutationMatrix[i] - 1];
                #endregion
                #region 6- permutation matrix (right part) XOR Left part --Message-- //Checked\\
                BitArray leftPart = new BitArray(32);
                for (int i = 0; i < 32; i++)
                    leftPart[i] = plainWith64Bit[i];
                BitArray rightXORleft = leftPart.Xor(matrixAfterPermutation);
                #endregion
                #region 7- Build the new matrix --Message-- //Checked\\
                BitArray newMatrix = new BitArray(64);
                for (int i = 0; i < 64; i++)
                {
                    if (i > 31)
                        newMatrix[i] = rightXORleft[i - 32];
                    else
                        newMatrix[i] = plainWith64Bit[i + 32];
                }
                #endregion
                plainWith64Bit = newMatrix;

            }
            #endregion
            #region 32bit Swap //Checked\\
            for (int i = 0; i < 32; i++)
            {
                bool tempBool = plainWith64Bit[i];
                plainWith64Bit[i] = plainWith64Bit[i + 32];
                plainWith64Bit[i + 32] = tempBool;
            }
            #endregion
            #region inverseIP //Checked\\
            int[] ipInverse = {40,8,48,16,56,24,64,32,
                                39,7,47,15,55,23,63,31,
                                38,6,46,14,54,22,62,30,
                                37,5,45,13,53,21,61,29,
                                36,4,44,12,52,20,60,28,
                                35,3,43,11,51,19,59,27,
                                34,2,42,10,50,18,58,26,
                                33,1,41,9,49,17,57,25};
            BitArray finalMatrix = new BitArray(64);
            for (int i = 0; i < 64; i++)
                finalMatrix[i] = plainWith64Bit[ipInverse[i] - 1];
            #endregion
            BitArray tempNew = new BitArray(4);
            StringBuilder result = new StringBuilder(18);
            result.Append("0x");
            for(int i = 0; i < 16; i++)
            {
                tempNew[0] = finalMatrix[(i*4) + 3];
                tempNew[1] = finalMatrix[(i * 4) + 2];
                tempNew[2] = finalMatrix[(i * 4) + 1];
                tempNew[3] = finalMatrix[(i * 4) + 0];
                byte[] tempByte = new byte[1];
                tempNew.CopyTo(tempByte, 0);
                result.AppendFormat("{0:x1}", tempByte[0]);
            }

            return result.ToString();
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }


        private int getIntFromBitArray(BitArray bitArray)
        {
            int[] array = new int[1];
            bitArray.CopyTo(array, 0);
            return array[0];
        }
        private BitArray getBitArray4BitFromInt(int num)
        {
            BitArray bits = new BitArray(4);
            BitArray temp = new BitArray(BitConverter.GetBytes(num));
            bits[0] = temp[3]; bits[1] = temp[2]; bits[2] = temp[1]; bits[3] = temp[0];
            return bits;
        }

        private BitArray swapBitArray(BitArray array)
        {
            for (int i = 0; i < array.Length; i += 4)
            {
                bool temp = array[i];
                array[i] = array[i + 3];
                array[i + 3] = temp;

                temp = array[i + 1];
                array[i + 1] = array[i + 2];
                array[i + 2] = temp;
            }
            for (int i = 0; i < array.Length; i += 8)
            {
                for(int j = 0; j < 4; j++)
                {
                    bool temp = array[i + j];
                    array[i + j] = array[i + 4 + j];
                    array[i + 4 + j] = temp;
                }
            }

            return array;
        }

    }
}
