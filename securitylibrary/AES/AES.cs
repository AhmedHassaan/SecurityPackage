using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Collections;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();

            Byte bz = 0x0a;
            String bbz = bz.ToString("x");
            key = key.Remove(0, 2);
            cipherText = cipherText.Remove(0, 2);
            key = key.ToLower();
            cipherText = cipherText.ToLower();
            string plain = "";
            string[,] inversemixColumnsMatrix = new string[4, 4];
            List<string[,]> keys = new List<string[,]>();
            Dictionary<string, string> sbox;
            byte[,] inverseSBox;
            string[,] RCON;
            string[,] keyMatrix = new string[4, 4];
            string[,] cipherMatrix = new string[4, 4];
            #region RCON
            RCON = new string[4, 10] { {"01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" } ,
                                                 {"00","00","00","00","00","00","00","00","00","00", },
                                                 {"00","00","00","00","00","00","00","00","00","00", },
                                                 {"00","00","00","00","00","00","00","00","00","00", }};
            #endregion
            #region SBox Map
            sbox = new Dictionary<string, string>();
            sbox.Add("00", "63"); sbox.Add("01", "7c"); sbox.Add("02", "77"); sbox.Add("03", "7b"); sbox.Add("04", "f2");
            sbox.Add("05", "6b"); sbox.Add("06", "6f"); sbox.Add("07", "c5"); sbox.Add("08", "30"); sbox.Add("09", "01");
            sbox.Add("0a", "67"); sbox.Add("0b", "2b"); sbox.Add("0c", "fe"); sbox.Add("0d", "d7"); sbox.Add("0e", "ab"); sbox.Add("0f", "76");
            sbox.Add("10", "ca"); sbox.Add("11", "82"); sbox.Add("12", "c9"); sbox.Add("13", "7d"); sbox.Add("14", "fa"); sbox.Add("15", "59");
            sbox.Add("16", "47"); sbox.Add("17", "f0"); sbox.Add("18", "ad"); sbox.Add("19", "d4"); sbox.Add("1a", "a2");
            sbox.Add("1b", "af"); sbox.Add("1c", "9c"); sbox.Add("1d", "a4"); sbox.Add("1e", "72"); sbox.Add("1f", "c0");
            sbox.Add("20", "b7"); sbox.Add("21", "fd"); sbox.Add("22", "93"); sbox.Add("23", "26"); sbox.Add("24", "36");
            sbox.Add("25", "3f"); sbox.Add("26", "f7"); sbox.Add("27", "cc"); sbox.Add("28", "34"); sbox.Add("29", "a5");
            sbox.Add("2a", "e5"); sbox.Add("2b", "f1"); sbox.Add("2c", "71"); sbox.Add("2d", "d8"); sbox.Add("2e", "31"); sbox.Add("2f", "15");
            sbox.Add("30", "04"); sbox.Add("31", "c7"); sbox.Add("32", "23"); sbox.Add("33", "c3"); sbox.Add("34", "18"); sbox.Add("35", "96");
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
            #region Inverse SBox
            inverseSBox = new byte[16, 16] {
                            /* 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f */
                            /*0*/  {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
                            /*1*/  {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
                            /*2*/  {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
                            /*3*/  {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
                            /*4*/  {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
                            /*5*/  {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
                            /*6*/  {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
                            /*7*/  {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
                            /*8*/  {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                            /*9*/  {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
                            /*a*/  {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
                            /*b*/  {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
                            /*c*/  {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
                            /*d*/  {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
                            /*e*/  {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
                            /*f*/  {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };

            #endregion
            #region Generate Keys
            string keyTemp = key;
            int countKey = 0;
            int countPlain = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    keyMatrix[j, i] = key[countKey++].ToString() + key[countKey++].ToString();
                    cipherMatrix[j, i] = cipherText[countPlain++].ToString() + cipherText[countPlain++].ToString();
                }
            }

            keys.Add(keyMatrix);
            int RCONCount = 0;
            for (int i = 0; i < 10; i++)
            {
                string[,] trashTemp = keyMatrix;
                keyMatrix = new string[4, 4];
                for (int j = 0; j < 4; j++)
                {
                    if (j == 0)
                    {
                        for (int k = 0; k < 4; k++)
                            keyMatrix[k, j] = sbox[trashTemp[(k + 1) % 4, j + 3]];
                        for (int k = 0; k < 4; k++)
                        {
                            int num1 = Convert.ToInt32(trashTemp[k, j], 16);
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
            // swap keys instead of work from index 16
            for(int i = 0; i <= keys.Count / 2; i++)
            {
                string[,] tempK = keys[i];
                keys[i] = keys[keys.Count - 1 - i];
                keys[keys.Count - 1 - i] = tempK;
            }
            #endregion
            #region Build Mix Columns Matrix
            inversemixColumnsMatrix[0, 0] = "0e";
            inversemixColumnsMatrix[0, 1] = "0b";
            inversemixColumnsMatrix[0, 2] = "0d";
            inversemixColumnsMatrix[0, 3] = "09";
            for (int i = 1; i < 4; i++)
            {
                string t = inversemixColumnsMatrix[i - 1, 3];
                inversemixColumnsMatrix[i, 1] = inversemixColumnsMatrix[i - 1, 0];
                inversemixColumnsMatrix[i, 2] = inversemixColumnsMatrix[i - 1, 1];
                inversemixColumnsMatrix[i, 3] = inversemixColumnsMatrix[i - 1, 2];
                inversemixColumnsMatrix[i, 0] = t;
            }
            #endregion
            #region Start Decryption
            keyMatrix = keys[0];
            #region Initial round (Add Round Key) //Checked\\
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int num1 = Convert.ToInt32(cipherMatrix[j, i], 16);
                    int num2 = Convert.ToInt32(keyMatrix[j, i], 16);
                    int result = num1 ^ num2;
                    cipherMatrix[j, i] = result.ToString("x");
                    if (cipherMatrix[j, i].Length == 1)
                        cipherMatrix[j, i] = "0" + cipherMatrix[j, i];
                }
            }
            #endregion
            #region Main Rounds (9)
            for (int i = 1; i <= 9; i++)
            {
                #region 1- Inverse Shift Row //Checked\\
                for (int a = 1; a < 4; a++)
                {
                    for (int b = 0; b < a; b++)
                    {
                        string t = cipherMatrix[a, 3];
                        cipherMatrix[a, 3] = cipherMatrix[a, 2];
                        cipherMatrix[a, 2] = cipherMatrix[a, 1];
                        cipherMatrix[a, 1] = cipherMatrix[a, 0];
                        cipherMatrix[a, 0] = t;
                    }
                }
                #endregion
                #region 2- Inverse Sub Byte //Done\\ //Checked\\
                for (int a = 0; a < 4; a++)
                    for (int b = 0; b < 4; b++) {
                        int row = 0;
                        int col = 0;
                        if (cipherMatrix[b, a][0] <= '9')
                            row = cipherMatrix[b, a][0] - '0';
                        else if (cipherMatrix[b, a][0] >= 'a')
                            row = cipherMatrix[b, a][0] - 'a' + 10;
                        if (cipherMatrix[b, a][1] <= '9')
                            col = cipherMatrix[b, a][1] - '0';
                        else if (cipherMatrix[b, a][1] >= 'a')
                            col = cipherMatrix[b, a][1] - 'a' + 10;
                        cipherMatrix[b, a] = inverseSBox[row,col].ToString("x");
                        if (cipherMatrix[b, a].Length == 1)
                            cipherMatrix[b, a] = "0" + cipherMatrix[b, a];
                    }
                #endregion
                #region 3- Add Round //Done\\ //Checked\\
                for (int a = 0; a < 4; a++)
                {
                    for (int b = 0; b < 4; b++)
                    {
                        int num1 = Convert.ToInt32(cipherMatrix[b, a], 16);
                        int num2 = Convert.ToInt32(keys[i][b, a], 16);
                        int result = num1 ^ num2;
                        cipherMatrix[b, a] = result.ToString("x");
                        if (cipherMatrix[b, a].Length == 1)
                            cipherMatrix[b, a] = "0" + cipherMatrix[b, a];
                    }
                }
                #endregion
                #region 4- Inverse mix columns



                List<BitArray> binaries = new List<BitArray>();
                string[,] tempPlain = new string[4, 1];
                BitArray binary;
                int tempCipher = 0;
                for (int k = 0; k < 4; k++)
                {
                    for (int a = 0; a < 4; a++)
                    {
                        for (int b = 0; b < 4; b++)
                        {
                            binary = getBinary(cipherMatrix[b, k]);
                            if (inversemixColumnsMatrix[a, b] == "09")
                            {
                                for (int zz = 0; zz < 3; zz++)
                                {
                                    bool firstBit = binary[0];
                                    for (int z = 0; z < 7; z++)
                                        binary[z] = binary[z + 1];
                                    binary[7] = false;
                                    if (firstBit)
                                    {
                                        BitArray binary2 = getBinary("1b");
                                        binary = binary.Xor(binary2);
                                    }
                                }
                                binary = binary.Xor(getBinary(cipherMatrix[b, k]));
                            }
                            else if (inversemixColumnsMatrix[a, b] == "0b")
                            {
                                for (int zz = 0; zz < 3; zz++)
                                {
                                    bool firstBit = binary[0];
                                    for (int z = 0; z < 7; z++)
                                        binary[z] = binary[z + 1];
                                    binary[7] = false;
                                    if (firstBit)
                                    {
                                        BitArray binary2 = getBinary("1b");
                                        binary = binary.Xor(binary2);
                                    }
                                    if (zz == 1)
                                        binary = binary.Xor(getBinary(cipherMatrix[b, k]));
                                }
                                binary = binary.Xor(getBinary(cipherMatrix[b, k]));
                            }
                            else if (inversemixColumnsMatrix[a, b] == "0d")
                            {
                                for (int zz = 0; zz < 3; zz++)
                                {
                                    bool firstBit = binary[0];
                                    for (int z = 0; z < 7; z++)
                                        binary[z] = binary[z + 1];
                                    binary[7] = false;
                                    if (firstBit)
                                    {
                                        BitArray binary2 = getBinary("1b");
                                        binary = binary.Xor(binary2);
                                    }
                                    if (zz == 0)
                                        binary = binary.Xor(getBinary(cipherMatrix[b, k]));
                                }
                                binary = binary.Xor(getBinary(cipherMatrix[b, k]));
                            }
                            else if (inversemixColumnsMatrix[a, b] == "0e")
                            {
                                for (int zz = 0; zz < 3; zz++)
                                {
                                    bool firstBit = binary[0];
                                    for (int z = 0; z < 7; z++)
                                        binary[z] = binary[z + 1];
                                    binary[7] = false;
                                    if (firstBit)
                                    {
                                        BitArray binary2 = getBinary("1b");
                                        binary = binary.Xor(binary2);
                                    }
                                    if (zz == 0)
                                        binary = binary.Xor(getBinary(cipherMatrix[b, k]));
                                    if (zz == 1)
                                        binary = binary.Xor(getBinary(cipherMatrix[b, k]));
                                }
                            }
                            binaries.Add(binary);
                        }
                        for (int z = 1; z < binaries.Count; z++)
                            binaries[z] = binaries[z - 1].Xor(binaries[z]);
                        tempPlain[a, 0] = getHex(binaries[binaries.Count - 1]);
                        binaries = new List<BitArray>();
                    }
                    for (int p = 0; p < 4; p++)
                        cipherMatrix[p, k] = tempPlain[p, 0];
                }


                #endregion
            }
            #endregion
            #region Final Round
            #region 1- Inverse Shift Row
            for (int a = 1; a < 4; a++)
            {
                for (int b = 0; b < a; b++)
                {
                    string t = cipherMatrix[a, 3];
                    cipherMatrix[a, 3] = cipherMatrix[a, 2];
                    cipherMatrix[a, 2] = cipherMatrix[a, 1];
                    cipherMatrix[a, 1] = cipherMatrix[a, 0];
                    cipherMatrix[a, 0] = t;
                }
            }
            #endregion
            #region 2- Inverse Sub Byte //Done\\
            for (int a = 0; a < 4; a++)
                for (int b = 0; b < 4; b++)
                {
                    int row = 0;
                    int col = 0;
                    if (cipherMatrix[b, a][0] <= '9')
                        row = cipherMatrix[b, a][0] - '0';
                    else if (cipherMatrix[b, a][0] >= 'a')
                        row = cipherMatrix[b, a][0] - 'a' + 10;
                    if (cipherMatrix[b, a][1] <= '9')
                        col = cipherMatrix[b, a][1] - '0';
                    else if (cipherMatrix[b, a][1] >= 'a')
                        col = cipherMatrix[b, a][1] - 'a' + 10;
                    cipherMatrix[b, a] = inverseSBox[row, col].ToString("x");
                    if (cipherMatrix[b, a].Length == 1)
                        cipherMatrix[b, a] = "0" + cipherMatrix[b, a];
                }
            #endregion
            #region 3- Add Round //Done\\
            for (int a = 0; a < 4; a++)
            {
                for (int b = 0; b < 4; b++)
                {
                    int num1 = Convert.ToInt32(cipherMatrix[b, a], 16);
                    int num2 = Convert.ToInt32(keys[10][b, a], 16);
                    int result = num1 ^ num2;
                    cipherMatrix[b, a] = result.ToString("x");
                    if (cipherMatrix[b, a].Length == 1)
                        cipherMatrix[b, a] = "0" + cipherMatrix[b, a];
                }
            }
            #endregion
            #endregion
            #endregion
            plain += "0x";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    plain += cipherMatrix[j, i];
            return plain;
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
            Dictionary<string, string> sbox;
            string[,] RCON;
            #region RCON
            RCON = new string[4, 10] { {"01", "02", "04", "08", "10", "20", "40", "80", "1b", "36" } ,
                                                 {"00","00","00","00","00","00","00","00","00","00", },
                                                 {"00","00","00","00","00","00","00","00","00","00", },
                                                 {"00","00","00","00","00","00","00","00","00","00", }};
            #endregion
            #region SBox Map
            sbox = new Dictionary<string, string>();
            sbox.Add("00", "63"); sbox.Add("01", "7c"); sbox.Add("02", "77"); sbox.Add("03", "7b"); sbox.Add("04", "f2");
            sbox.Add("05", "6b"); sbox.Add("06", "6f"); sbox.Add("07", "c5"); sbox.Add("08", "30"); sbox.Add("09", "01");
            sbox.Add("0a", "67"); sbox.Add("0b", "2b"); sbox.Add("0c", "fe"); sbox.Add("0d", "d7"); sbox.Add("0e", "ab"); sbox.Add("0f", "76");
            sbox.Add("10", "ca"); sbox.Add("11", "82"); sbox.Add("12", "c9"); sbox.Add("13", "7d"); sbox.Add("14", "fa"); sbox.Add("15", "59");
            sbox.Add("16", "47"); sbox.Add("17", "f0"); sbox.Add("18", "ad"); sbox.Add("19", "d4"); sbox.Add("1a", "a2");
            sbox.Add("1b", "af"); sbox.Add("1c", "9c"); sbox.Add("1d", "a4"); sbox.Add("1e", "72"); sbox.Add("1f", "c0");
            sbox.Add("20", "b7"); sbox.Add("21", "fd"); sbox.Add("22", "93"); sbox.Add("23", "26"); sbox.Add("24", "36");
            sbox.Add("25", "3f"); sbox.Add("26", "f7"); sbox.Add("27", "cc"); sbox.Add("28", "34"); sbox.Add("29", "a5");
            sbox.Add("2a", "e5"); sbox.Add("2b", "f1"); sbox.Add("2c", "71"); sbox.Add("2d", "d8"); sbox.Add("2e", "31"); sbox.Add("2f", "15");
            sbox.Add("30", "04"); sbox.Add("31", "c7"); sbox.Add("32", "23"); sbox.Add("33", "c3"); sbox.Add("34", "18"); sbox.Add("35", "96");
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
            #region Key Generator //Correct\\
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
                for(int j = 0; j < 4; j++)
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
                string t = mixColumnsMatrix[i - 1, 3];
                mixColumnsMatrix[i, 1] = mixColumnsMatrix[i - 1, 0];
                mixColumnsMatrix[i, 2] = mixColumnsMatrix[i - 1, 1];
                mixColumnsMatrix[i, 3] = mixColumnsMatrix[i - 1, 2];
                mixColumnsMatrix[i, 0] = t;
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
                    for (int b = 0; b < a; b++)
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
                List<BitArray> binaries = new List<BitArray>();
                string[,] tempPlain = new string[4, 1];
                for(int k = 0; k < 4; k++)
                {
                    for (int a = 0; a < 4; a++)
                    {
                        for (int b = 0; b < 4; b++)
                        {
                            if (mixColumnsMatrix[a, b] == "02")
                            {
                                BitArray binary = getBinary(plainMatrix[b, k]);
                                bool firstBit = binary[0];
                                for (int z = 0; z < 7; z++)
                                    binary[z] = binary[z + 1];
                                binary[7] = false;
                                if (firstBit)
                                {
                                    BitArray binary2 = getBinary("1b");
                                    binary = binary.Xor(binary2);
                                }
                                binaries.Add(binary);
                            }
                            else if (mixColumnsMatrix[a, b] == "03")
                            {
                                BitArray binary = getBinary(plainMatrix[b, k]);
                                bool firstBit = binary[0];
                                for (int z = 0; z < 7; z++)
                                    binary[z] = binary[z + 1];
                                binary[7] = false;
                                if (firstBit)
                                {
                                    BitArray binary2 = getBinary("1b");
                                    binary = binary.Xor(binary2);
                                }
                                BitArray temp = getBinary(plainMatrix[b, k]);
                                binary = binary.Xor(temp);
                                binaries.Add(binary);
                            }
                            else
                            {
                                BitArray binary = getBinary(plainMatrix[b, k]);
                                binaries.Add(binary);
                            }
                        }
                        for (int z = 1; z < 4; z++)
                            binaries[z] = binaries[z - 1].Xor(binaries[z]);
                        tempPlain[a, 0] = getHex(binaries[3]);
                            binaries = new List<BitArray>();
                    }
                    for (int p = 0; p < 4; p++)
                        plainMatrix[p, k] = tempPlain[p, 0];
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
                for (int b = 0; b < a; b++)
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
        private BitArray getBinary(string hex)
        {
            //string binary = "";
            Byte[] bytes = Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
            BitArray bitArray = new BitArray(bytes);
            for(int i = 0; i < bitArray.Length/2; i++)
            {
                bool t = bitArray[i];
                bitArray[i] = bitArray[bitArray.Length - 1 - i];
                bitArray[bitArray.Length - 1 - i] = t;
            }
            //for (int i = 0; i < 8; i++)
            //    binary += bitArray[bitArray.Length - i - 1] ? "1" : "0";
            return bitArray;
        }
        private string getHex(BitArray bits)
        {
            for (int i = 0; i < bits.Length / 2; i++)
            {
                bool t = bits[i];
                bits[i] = bits[bits.Length - 1 - i];
                bits[bits.Length - 1 - i] = t;
            }
            for(int i = 0; i < 4; i++)
            {
                bool t = bits[i];
                bits[i] = bits[i + 4];
                bits[i + 4] = t;
            }

            StringBuilder result = new StringBuilder(18);
            BitArray tempNew = new BitArray(4);
            for (int i = 0; i < 2; i++)
            {
                tempNew[3] = bits[(i * 4) + 3];
                tempNew[2] = bits[(i * 4) + 2];
                tempNew[1] = bits[(i * 4) + 1];
                tempNew[0] = bits[(i * 4) + 0];
                byte[] tempByte = new byte[1];
                tempNew.CopyTo(tempByte, 0);
                result.AppendFormat("{0:x1}", tempByte[0]);
            }
            //hex = result.ToString();
            //if (hex.Length == 1)
            //    hex = "0" + hex;
            return result.ToString();
        }
    }
}
