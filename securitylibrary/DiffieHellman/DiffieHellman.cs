using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            int[] keys = new int[2];
            int ya = 0, yb = 0;
            ya = alpha % q;
            for (int i = 1; i < xa; i++)
                ya = (ya * alpha) % q;
            yb = alpha % q;
            for (int i = 1; i < xb; i++)
                yb = (yb * alpha) % q;
            keys[0] = yb % q;
            for (int i = 1; i < xa; i++)
                keys[0] = (keys[0] * yb) % q;
            keys[1] = ya % q;
            for (int i = 1; i < xb; i++)
                keys[1] = (keys[1] * ya) % q;
            return keys.ToList();
        }
    }
}
