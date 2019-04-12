using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            // C = M^e mod n
            // e < Qn and gcd(e,Qn)) = 1
            int n = p * q;
            int C = M % n;
            for(int i=1;i< e; i++)
                C = (C * M) % n;
            return C;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();
            // M = C^d mod n
            // d = e^-1 mod Qn
            int n = p * q;
            int Qn = (p - 1) * (q - 1);
            int d = extendedEcluidean(e, Qn);
            int M = C % n;
            for (int i = 1; i < d; i++)
                M = (M * C) % n;
            return M;
        }
        private int extendedEcluidean(int number, int baseN)
        {
            int[] As = new int[3];
            int[] Bs = new int[3];
            int[] Ts = new int[3];
            As[0] = 1; As[1] = 0; As[2] = baseN;
            Bs[0] = 0; Bs[1] = 1; Bs[2] = number;
            while (true)
            {
                if (Bs[2] == 0)
                {
                    return -1;
                }
                else if (Bs[2] == 1)
                {
                    Bs[1] %= baseN;
                    while (Bs[1] < 0)
                        Bs[1] += baseN;
                    return Bs[1];
                }
                int q = As[2] / Bs[2];
                Ts[0] = As[0] - (q * Bs[0]); Ts[1] = As[1] - (q * Bs[1]); Ts[2] = As[2] - (q * Bs[2]);
                As[0] = Bs[0]; As[1] = Bs[1]; As[2] = Bs[2];
                Bs[0] = Ts[0]; Bs[1] = Ts[1]; Bs[2] = Ts[2];
            }
        }

    }
}
