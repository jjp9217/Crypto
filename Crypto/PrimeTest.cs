//Jesse Pingitore
using System;
using System.Numerics;

namespace Crypto
{
    /// <summary>
    /// A separate, static class that exists to hold a needed extension method for verifying primality up to a given
    /// certainty. No known method other than exhaustive division can prove a number prime, but this method can prove
    /// a number is likely to be prime. 
    /// </summary>
    public static class PrimeTest
    {

        /// <summary>
        /// This method reasonably tests whether a given BigInteger is prime. 
        /// </summary>
        /// <param name="value">An odd integer to test primality. Presumed greater than 3.</param>
        /// <param name="k">The "reasonable" number of testing rounds to perform. Default value is ten.</param>
        /// <returns>Is this number probably prime?</returns>
        public static Boolean IsProbablyPrime(this BigInteger value, int k = 10)
        {
            //establish essential values
            var foundVals = FindD(value, BigInteger.Subtract(value, 1), 0);
            var d = foundVals[0];
            var r = foundVals[1];

            //establish local reusable values
            var aGen = new Random(); // to generate a random number
            var valueMinusTwo = BigInteger.Subtract(value, 2);
            var bitLen = value.GetBitLength();

           for (var i = 0; i < k; i++) //Witness Loop
           {

               BigInteger a;
               byte[] bytes = new byte[ (bitLen + 1) / 8 ]; 
               //NOTE: This will re-create a number with a bit length ONE LESS than the value. This will assist in 
               // overshooting (n-2) greatly, at the cost of some legitimate search space. 
               
               do
               {
                   aGen.NextBytes(bytes);
                   a = BigInteger.Abs(new BigInteger(bytes));
               } while (a > valueMinusTwo || a < 2);//if a < 2 or a > (n-2), roll a new number

               var x  = BigInteger.ModPow(a, d, value);

                if (x.Equals(BigInteger.One) || x.Equals(BigInteger.Subtract(value, BigInteger.One)))
                {
                    continue;
                }//else

                var continueWitnessFlag = false;
                for (var j = 0; j < r; j++) //if r is negative this never runs, flag never set
                {
                    x = BigInteger.ModPow(x,  2, value);
                    if(x.Equals(BigInteger.Subtract(value, BigInteger.One)))
                    {
                        continueWitnessFlag = true;
                        break;
                    }
                }

                if (continueWitnessFlag) continue; // the round is exhausted, try again
                
                //else
                return false; //the r-loop exhausted, without a continue flag, this is a proven composite number
            }

            return true; //the number could not be proven composite in k rounds, it is probably prime
        }

        /// <summary>
        /// Reduce an initial d = n-1 to a d which satisfies both (n = 2^r * d + 1), and (d mod 2 = 1).
        /// </summary>
        /// <param name="n"> The value from which we derive 'd'</param>
        /// <param name="d"> The value we are solving for. </param>
        /// <param name="r"> An iterating variable. </param>
        /// <returns>D</returns>
        private static BigInteger[] FindD(BigInteger n, BigInteger d, int r)
        {
            while (true)
            {
                var twoPower = BigInteger.Pow(2, r); // 2^r_i
                var twoProduct = BigInteger.Multiply(twoPower, d); // 2^r_i * d_i
                var twoPlus = BigInteger.Add(twoProduct, 1); // 2^r_i

                var equates = Equals(n, twoPlus);

                var dMod = BigInteger.ModPow(d, 1, 2);
                var dIsOdd = Equals(dMod, BigInteger.One);

                if (!(equates && dIsOdd)) // if one of these conditions are false, d must be reduced further
                {
                    d = BigInteger.Divide(d, 2); // d_i+1 = d / 2
                    r += 1; // r_i+1 = r+1
                    continue; //replaced initial recursive design with a loop for better performance
                }

                // if n = (2^r_i * d_i + 1) and d is odd, d is ready to return
                BigInteger[] returnWrapper = {d, r};
                return returnWrapper; 
            }
        }
    }
}