using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            //throw new NotImplementedException();
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
                    while(Bs[1] < 0)
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
