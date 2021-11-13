//Jesse Pingitore
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Crypto
{
    /// <summary>
    /// A program to generate prime numbers based off a given number of bits to the number. Uses a parallel loop
    /// to speed up computation. 
    /// Depends on PrimeTest.cs for verification of numbers via extension method isPossiblyPrime. May be replaced
    /// by another methods to verify primes if a more efficient option is found.
    /// </summary>
    public class PrimeGen
    {
        // The number of bits that out prime number may take up. Must be greater than 32, and a multiple of 8.
        private readonly int _bits;
        

        // We have this to prevent scenarios where one thread has just caused the _count to be reached, but another
        // has found a prime and is about to print it before the cancellation token may take effect.
        private static readonly object PrintingLock = new();
        
        // public static void Main(string[] args)
        // {
        //     ParseArgs(args); //initial setup and argument verification
        //     var aBits = int.Parse(args[0]);
        //
        //     var p = args.Length.Equals(2) ?
        //         new PrimeGen(aBits, int.Parse(args[1])) : new PrimeGen(aBits);
        //
        //     Console.WriteLine("BitLength: " + aBits);
        //     p.GeneratePrimes();
        // } 
        
        /// <summary>
        /// An object which can randomly generate and verify prime numbers.
        /// </summary>
        /// <param name="bits"></param> 
        /// <param name="count"></param>
        public PrimeGen(int bits)
        {
            this._bits = bits;
        }

        /// <summary>
        /// Generate n random prime numbers,verify they are reasonably prime, then return them. Optimizations can be
        /// found in the primitive prime checks, and race conditions are prevented via a combination of a lock and an
        /// active check to see if the thread has been cancelled, but has not yet responded to the cancellation.
        ///
        /// Depends on an extension method BigInteger.isPossiblePrime() to be in scope.
        /// </summary>
        /// <returns>void</returns>
        public List<BigInteger> GeneratePrimes(int count=1)
        {
            List<BigInteger> primes = new List<BigInteger>();
            var gen = new RNGCryptoServiceProvider();

            //setup control objects
            var numPrimesConfirmed = 1;
            var tokenSource = new CancellationTokenSource();
            var options = new ParallelOptions { CancellationToken = tokenSource.Token };
            options.CancellationToken.Register(() => { }); //just in case
            
            // Parallelize
            Parallel.For(0, int.MaxValue, (_, state) =>
            {
                if (tokenSource.IsCancellationRequested)
                {
                    state.Stop();
                } //for any threads just starting

                var bytes = new byte[(_bits / 8)]; //div bits by 8 to get byte size
                gen.GetBytes(bytes);

                var possiblePrime = BigInteger.Abs(new BigInteger(bytes));

                //trivial optimization: parity
                if (BigInteger.ModPow(possiblePrime, BigInteger.One, 2).Equals(BigInteger.Zero))
                { //even numbers are never prime, cut the search space in half!
                    return; //equivalent to continue in a parallel for loop
                }

                //trivial optimization: division by known small primes
                if (BigInteger.ModPow(possiblePrime, BigInteger.One, 3).Equals(BigInteger.Zero)
                    || BigInteger.ModPow(possiblePrime, BigInteger.One, 5).Equals(BigInteger.Zero)
                    || BigInteger.ModPow(possiblePrime, BigInteger.One, 7).Equals(BigInteger.Zero)
                    || BigInteger.ModPow(possiblePrime, BigInteger.One, 11).Equals(BigInteger.Zero))
                {
                    return; //primes are never divisible by other primes
                }

                if (possiblePrime <= 3 || possiblePrime.IsProbablyPrime()) // if (likely) prime
                {
                    // The combo of lock + token check prevents threads from rushing the WriteLine prior to 
                    // cancellation. Removing the lock will allow threads to flood the WriteLine prior to cancelling.
                    lock (PrintingLock)
                    {
                        if ((!tokenSource.IsCancellationRequested))
                            primes.Add(possiblePrime);

                        Interlocked.Increment(ref numPrimesConfirmed);
                        if (numPrimesConfirmed > count) //adjust for 1-based indexing via >, not ==
                        {
                            tokenSource.Cancel();// All primes found, issue the stop
                        }
                    }
                }
            });
            return primes;
        }
    }
}