//Jesse Pingitore

using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace Crypto
{
    public class Messenger
    {
        //used for generating p and q, they must sum to 1024 
        private const int DefaultBitSize = 1024;
        
        private readonly PrimeGen _generator;
        
        //The 'e' used in RSA. May be reused, and is small for performance.
        private const int E = 65537;

        public Messenger(int bitSize = DefaultBitSize)
        {
            this._generator = new PrimeGen(DefaultBitSize);
        }

        public static void Main(string[] args)
        {
            Messenger msgr = new Messenger();
            msgr.RSA();
        }
        private void RSA()
        {
            //first use PrimeGen to generate large numbers for P and Q
            List<BigInteger> primes = _generator.GeneratePrimes(2);

            var p = primes[0];
            var q = primes[1];
            var n = BigInteger.Multiply(p, q);

            var pMinusOne = BigInteger.Subtract(p, BigInteger.One);
            var qMinusOne = BigInteger.Subtract(q, BigInteger.One);
            var r = BigInteger.Multiply(pMinusOne, qMinusOne);

            var d = ModInverse(E, r); //using constant E
            
            


        }

        /// <summary>
        /// A method for finding the modular inverse of a BigInteger.
        /// </summary>
        /// <param name="a">The BigInteger to find the modInverse of.</param>
        /// <param name="r">The TODO </param>
        /// <returns>The modular inverse of a and r</returns>
        private BigInteger ModInverse(BigInteger a, BigInteger r)
        {
            BigInteger i = r, v = 0, d = 1;
            while (a>0) {
                BigInteger t = i/a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t*x;
                v = x;
            }
            v %= r;
            if (v<0) v = (v+r)%r;
            return v;
        }
        
        
    }
}