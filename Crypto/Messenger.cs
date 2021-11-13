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
    

        private PrimeGen generator;

        public Messenger(int bitSize = DefaultBitSize)
        {
            this.generator = new PrimeGen(DefaultBitSize);
        }

        public static void Main(string[] args)
        {
            Messenger msgr = new Messenger();
            msgr.RSA();
        }
        private void RSA()
        {
            //first use PrimeGen to generate large numbers for P and Q
            List<BigInteger> primes = generator.GeneratePrimes(2);

            var p = primes[0];
            var q = primes[1];
            var n = BigInteger.Multiply(p, q);
            
            

        }
        
        
    }
}