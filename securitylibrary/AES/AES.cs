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
            key = key.ToLower();
            plainText = plainText.ToLower();
            string[,] mixColumnsMatrix = new string[4, 4];
            List<string[,]> keys = new List<string[,]>();
            #region Key Generator
            string keyTemp = key;
            string[,] keyMatrix = new string[4, 4];
            string[,] plainMatrix = new string[4, 4];
            int countKey = 0;
            int countPlain = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keyMatrix[j, i] = key[countKey++].ToString() + key[countKey++].ToString();
                    plainMatrix[j, i] = plainText[countPlain++].ToString() + plainText[countPlain++].ToString();
                }
            }
            #region RCON
            string[,] RCON = new string[4, 10] { {"01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" } ,
                                                 {"00","00","00","00","00","00","00","00","00","00", },
                                                 {"00","00","00","00","00","00","00","00","00","00", },
                                                 {"00","00","00","00","00","00","00","00","00","00", }};
            #endregion
            #region SBox Map
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
            sbox.Add("40", "09"); sbox.Add("41", "83"); sbox.Add("42", "2c"); sbox.Add("43", "1a"); sbox.Add("44", "1b");
            sbox.Add("45", "6e"); sbox.Add("46", "5a"); sbox.Add("47", "a0"); sbox.Add("48", "52"); sbox.Add("49", "3b");
            sbox.Add("4a", "d6"); sbox.Add("4b", "b3"); sbox.Add("4c", "29"); sbox.Add("4d", "e3"); sbox.Add("4e", "2f"); sbox.Add("4f", "84");
            sbox.Add("50", "53"); sbox.Add("51", "d1"); sbox.Add("52", "00"); sbox.Add("53", "ed"); sbox.Add("54", "20"); sbox.Add("55", "fc");
            sbox.Add("56", "b1"); sbox.Add("57", "5b"); sbox.Add("58", "6a"); sbox.Add("59", "cb"); sbox.Add("5a", "be");
            sbox.Add("5b", "39"); sbox.Add("5c", "4a"); sbox.Add("5d", "4c"); sbox.Add("5e", "58"); sbox.Add("5f", "cf");
            sbox.Add("60", "d0"); sbox.Add("61", "ef"); sbox.Add("62", "aa"); sbox.Add("63", "fb"); sbox.Add("64", "43");
            sbox.Add("65", "4d"); sbox.Add("66", "33"); sbox.Add("67", "85"); sbox.Add("68", "45"); sbox.Add("69", "f9");
            sbox.Add("6a", "02"); sbox.Add("6b", "7f"); sbox.Add("6c", "50"); sbox.Add("6d", "3c"); sbox.Add("6e", "9f"); sbox.Add("6f", "a8");
            sbox.Add("70", "51"); sbox.Add("71", "a3"); sbox.Add("72", "40"); sbox.Add("73", "8f"); sbox.Add("74", "92"); sbox.Add("75", "9d");
            sbox.Add("76", "38"); sbox.Add("77", "f5"); sbox.Add("78", "bc"); sbox.Add("79", "b6"); sbox.Add("7a", "da");
            sbox.Add("7b", "21"); sbox.Add("7c", "10"); sbox.Add("7d", "ff"); sbox.Add("7e", "f3"); sbox.Add("7f", "d2");
            sbox.Add("80", "cd"); sbox.Add("81", "0c"); sbox.Add("82", "13"); sbox.Add("83", "ec"); sbox.Add("84", "5f");
            sbox.Add("85", "97"); sbox.Add("86", "44"); sbox.Add("87", "17"); sbox.Add("88", "c4"); sbox.Add("89", "a7");
            sbox.Add("8a", "7e"); sbox.Add("8b", "3d"); sbox.Add("8c", "64"); sbox.Add("8d", "5d"); sbox.Add("8e", "19"); sbox.Add("8f", "73");
            sbox.Add("90", "60"); sbox.Add("91", "81"); sbox.Add("92", "4f"); sbox.Add("93", "dc"); sbox.Add("94", "22"); sbox.Add("95", "2a");
            sbox.Add("96", "90"); sbox.Add("97", "88"); sbox.Add("98", "46"); sbox.Add("99", "ee"); sbox.Add("9a", "b8");
            sbox.Add("9b", "14"); sbox.Add("9c", "de"); sbox.Add("9d", "5e"); sbox.Add("9e", "0b"); sbox.Add("9f", "db");
            sbox.Add("a0", "e0"); sbox.Add("a1", "32"); sbox.Add("a2", "3a"); sbox.Add("a3", "0a"); sbox.Add("a4", "49");
            sbox.Add("a5", "06"); sbox.Add("a6", "24"); sbox.Add("a7", "5c"); sbox.Add("a8", "c2"); sbox.Add("a9", "d3");
            sbox.Add("aa", "ac"); sbox.Add("ab", "62"); sbox.Add("ac", "91"); sbox.Add("ad", "95"); sbox.Add("ae", "e4"); sbox.Add("af", "79");
            sbox.Add("b0", "e7"); sbox.Add("b1", "c8"); sbox.Add("b2", "37"); sbox.Add("b3", "6d"); sbox.Add("b4", "8d"); sbox.Add("b5", "d5");
            sbox.Add("b6", "4e"); sbox.Add("b7", "a9"); sbox.Add("b8", "6c"); sbox.Add("b9", "56"); sbox.Add("ba", "f4");
            sbox.Add("bb", "ea"); sbox.Add("bc", "65"); sbox.Add("bd", "7a"); sbox.Add("be", "ae"); sbox.Add("bf", "08");
            sbox.Add("c0", "ba"); sbox.Add("c1", "78"); sbox.Add("c2", "25"); sbox.Add("c3", "2e"); sbox.Add("c4", "1c");
            sbox.Add("c5", "a6"); sbox.Add("c6", "b4"); sbox.Add("c7", "c6"); sbox.Add("c8", "e8"); sbox.Add("c9", "dd");
            sbox.Add("ca", "74"); sbox.Add("cb", "1f"); sbox.Add("cc", "4b"); sbox.Add("cd", "bd"); sbox.Add("ce", "8b"); sbox.Add("cf", "8a");
            sbox.Add("d0", "70"); sbox.Add("d1", "3e"); sbox.Add("d2", "b5"); sbox.Add("d3", "66"); sbox.Add("d4", "48"); sbox.Add("d5", "03");
            sbox.Add("d6", "f6"); sbox.Add("d7", "0e"); sbox.Add("d8", "61"); sbox.Add("d9", "35"); sbox.Add("da", "57");
            sbox.Add("db", "b9"); sbox.Add("dc", "86"); sbox.Add("dd", "c1"); sbox.Add("de", "1d"); sbox.Add("df", "9e");
            sbox.Add("e0", "e1"); sbox.Add("e1", "f8"); sbox.Add("e2", "98"); sbox.Add("e3", "11"); sbox.Add("e4", "69");
            sbox.Add("e5", "d9"); sbox.Add("e6", "8e"); sbox.Add("e7", "94"); sbox.Add("e8", "9b"); sbox.Add("e9", "1e");
            sbox.Add("ea", "87"); sbox.Add("eb", "e9"); sbox.Add("ec", "ce"); sbox.Add("ed", "55"); sbox.Add("ee", "28"); sbox.Add("ef", "df");
            sbox.Add("f0", "8c"); sbox.Add("f1", "a1"); sbox.Add("f2", "89"); sbox.Add("f3", "0d"); sbox.Add("f4", "bf"); sbox.Add("f5", "e6");
            sbox.Add("f6", "42"); sbox.Add("f7", "68"); sbox.Add("f8", "41"); sbox.Add("f9", "99"); sbox.Add("fa", "2d");
            sbox.Add("fb", "0f"); sbox.Add("fc", "b0"); sbox.Add("fd", "54"); sbox.Add("fe", "bb"); sbox.Add("ff", "16");
            #endregion
            keys.Add(keyMatrix);
            int RCONCount = 0;
            for(int i = 0; i < 10; i++)
            {
                string[,] trashTemp = keyMatrix;
                keyMatrix = new string[4, 4];
                for(int j = 0; j < 4; j++)
                {
                    if (j == 0)
                    {
                        for (int k = 0; k < 4; k++)
                            keyMatrix[k, j] = sbox[trashTemp[(k + 1) % 4, j + 3]];
                        for(int k = 0; k < 4; k++)
                        {
                            int num1 = Convert.ToInt32(trashTemp[k, j],16);
                            int num2 = Convert.ToInt32(keyMatrix[k, j], 16);
                            int num3 = Convert.ToInt32(RCON[k, RCONCount], 16);
                            int result = num1 ^ num2 ^ num3;
                            keyMatrix[k, j] = result.ToString("x");
                            if (keyMatrix[k, j].Length == 1)
                                keyMatrix[k, j] = "0" + keyMatrix[k, j];
                        }
                        RCONCount++;
                    }
                    else
                    {
                        for (int k = 0; k < 4; k++)
                        {
                            int num1 = Convert.ToInt32(trashTemp[k, j], 16);
                            int num2 = Convert.ToInt32(keyMatrix[k, j - 1], 16);
                            int result = num1 ^ num2;
                            keyMatrix[k, j] = result.ToString("x");
                            if (keyMatrix[k, j].Length == 1)
                                keyMatrix[k, j] = "0" + keyMatrix[k, j];
                        }
                    }
                }
                keys.Add(keyMatrix);
            }
            #endregion

            #region Start Encryption
            keyMatrix = keys[0];
            #region Initial round (Add Round Key)
            for (int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 0; j++)
                {
                    int num1 = Convert.ToInt32(plainMatrix[j, i], 16);
                    int num2 = Convert.ToInt32(keyMatrix[j, i], 16);
                    int result = num1 ^ num2;
                    plainMatrix[j, i] = result.ToString("x");
                    if (plainMatrix[j, i].Length == 1)
                        plainMatrix[j, i] = "0" + plainMatrix[j, i];
                }
            }
            #endregion
            #region Build Mix Columns Matrix
            mixColumnsMatrix[0, 0] = "02";
            mixColumnsMatrix[0, 1] = "03";
            mixColumnsMatrix[0, 2] = "01";
            mixColumnsMatrix[0, 3] = "01";
            for(int i = 1; i < 4; i++)
            {
                string t = mixColumnsMatrix[i, 0];
                mixColumnsMatrix[i, 0] = mixColumnsMatrix[i, 1];
                mixColumnsMatrix[i, 1] = mixColumnsMatrix[i, 2];
                mixColumnsMatrix[i, 2] = mixColumnsMatrix[i, 3];
                mixColumnsMatrix[i, 3] = t;
            }
            #endregion
            #region Main rounds (9)
            for (int i = 1; i <= 9; i++)
            {
                #region 1- SubBytes
                for (int a = 0; a < 4; a++)
                    for(int b = 0; b < 4; b++)
                        plainMatrix[b, a] = sbox[plainMatrix[b, a]];
                #endregion
                #region 2- ShiftRows
                for (int a = 1; a < 4; a++)
                {
                    for (int b = 0; b <= a; b++)
                    {
                        string t = plainMatrix[a, 0];
                        plainMatrix[a, 0] = plainMatrix[a, 1];
                        plainMatrix[a, 1] = plainMatrix[a, 2];
                        plainMatrix[a, 2] = plainMatrix[a, 3];
                        plainMatrix[a, 3] = t;
                    }
                }
                #endregion
                #region 3- Mix Columns

                for(int a = 0; a < 4; a++)
                {

                }
                #endregion
                #region 4- Add Round Key
                for(int a = 0; a < 4; a++)
                {
                    for(int b = 0; b < 4; b++)
                    {
                        int num1 = Convert.ToInt32(plainMatrix[b, a], 16);
                        int num2 = Convert.ToInt32(keys[i][b, a], 16);
                        int result = num1 ^ num2;
                        plainMatrix[b, a] = result.ToString("x");
                        if (plainMatrix[b, a].Length == 1)
                            plainMatrix[b, a] = "0" + plainMatrix[b, a];
                    }
                }
                #endregion
            }
            #endregion
            #region Final Round
            #region 1- SubBytes
            for (int a = 0; a < 4; a++)
                for (int b = 0; b < 4; b++)
                    plainMatrix[b, a] = sbox[plainMatrix[b, a]];
            #endregion
            #region 2- ShiftRows
            for (int a = 1; a < 4; a++)
            {
                for (int b = 0; b <= a; b++)
                {
                    string t = plainMatrix[a, 0];
                    plainMatrix[a, 0] = plainMatrix[a, 1];
                    plainMatrix[a, 1] = plainMatrix[a, 2];
                    plainMatrix[a, 2] = plainMatrix[a, 3];
                    plainMatrix[a, 3] = t;
                }
            }
            #endregion
            #region 3- Add Round Key
            for (int a = 0; a < 4; a++)
            {
                for (int b = 0; b < 4; b++)
                {
                    int num1 = Convert.ToInt32(plainMatrix[b, a], 16);
                    int num2 = Convert.ToInt32(keys[10][b, a], 16);
                    int result = num1 ^ num2;
                    plainMatrix[b, a] = result.ToString("x");
                    if (plainMatrix[b, a].Length == 1)
                        plainMatrix[b, a] = "0" + plainMatrix[b, a];
                }
            }
            #endregion
            #endregion

            #endregion
            cipher += "0x";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    cipher += plainMatrix[j, i];

            return cipher;
        }
    }
}
