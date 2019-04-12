using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            //throw new NotImplementedException();
            long[] keys = new long[2];
            keys[0] = alpha % q;
            for (int i = 1; i < k; i++)
                keys[0] = (keys[0] * alpha) % q;
            int K = y % q;
            for (int i = 1; i < k; i++)
                K = (K * y) % q;
            keys[1] = (K * m) % q;
            return keys.ToList();

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            // M = c2 K^-1 mod q = (c2 mod q * k^-1 mod q) mod q
            int K = c1 % q;
            for (int i = 1; i < x; i++)
                K = (K * c1) % q;
            int temp = extendedEcluidean(K, q);
            int M = ((c2 % q) * temp) % q;
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
