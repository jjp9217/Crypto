//Jesse Pingitore
using System;
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
        // The total number of primes to fully calculate and verify. Defaults to 1.
        private readonly int _count;

        // We have this to prevent scenarios where one thread has just caused the _count to be reached, but another
        // has found a prime and is about to print it before the cancellation token may take effect.
        private static readonly object PrintingLock = new();
        
        public static void Main(string[] args)
        {
            ParseArgs(args); //initial setup and argument verification
            var aBits = int.Parse(args[0]);

            var p = args.Length.Equals(2) ?
                new PrimeGen(aBits, int.Parse(args[1])) : new PrimeGen(aBits);

            Console.WriteLine("BitLength: " + aBits);
            p.GeneratePrimes();
        } 
        
        /// <summary>
        /// An object which can randomly generate and verify prime numbers.
        /// </summary>
        /// <param name="bits"></param> 
        /// <param name="count"></param>
        private PrimeGen(int bits, int count=1)
        {
            this._bits = bits;
            this._count = count;
        }

     
        /// <summary>
        /// Generate n random prime numbers,verify they are reasonably prime, then return them. Optimizations can be
        /// found in the primitive prime checks, and race conditions are prevented via a combination of a lock and an
        /// active check to see if the thread has been cancelled, but has not yet responded to the cancellation.
        ///
        /// Depends on an extension method BigInteger.isPossiblePrime() to be in scope.
        /// </summary>
        /// <returns>void</returns>
        private void GeneratePrimes()
        {
            
            var gen = new RNGCryptoServiceProvider();
            var time = new Stopwatch();

            //setup control objects
            var numPrimesConfirmed = 1;
            var tokenSource = new CancellationTokenSource();
            var options = new ParallelOptions { CancellationToken = tokenSource.Token };
            options.CancellationToken.Register(() => { }); //just in case
            
            // Parallelize
            time.Start();
            Parallel.For(0, int.MaxValue, (_, state) =>
            {
                if(tokenSource.IsCancellationRequested) { state.Stop(); } //for any threads just starting

                var bytes = new byte[ ( _bits / 8 )]; //div bits by 8 to get byte size
                gen.GetBytes(bytes);

                var possiblePrime =  BigInteger.Abs( new BigInteger(bytes));
                
                //trivial optimization: parity
                if(BigInteger.ModPow(possiblePrime, BigInteger.One, 2).Equals(BigInteger.Zero))
                {//even numbers are never prime, cut the search space in half!
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
                        var outString = numPrimesConfirmed + ": " + possiblePrime;
                        //if not one before reaching the count, append a newline as well
                        if ((numPrimesConfirmed) < _count)
                        {
                            outString += "\n";
                        }
                        
                        if( (! tokenSource.IsCancellationRequested)) 
                            Console.WriteLine(outString);

                        Interlocked.Increment(ref numPrimesConfirmed);
                        if (numPrimesConfirmed > _count) //adjust for 1-based indexing via >, not ==
                        {
                            tokenSource.Cancel();
                            time.Stop(); // All primes found, stop the clock
                        }
                    }
                }
            });
            Console.WriteLine("Time to Generate: {0}",time.Elapsed);
        }

        /// <summary>
        /// This method will exit the program in the event of malformed input.
        /// </summary>
        /// <param name="args">The console arguments</param>
        private static void ParseArgs(string[] args)
        {
            if (args.Length < 1 || args[0].Contains('h')) //the bits arg was excluded or a help message was attempted
            {
                PrintHelp();
                Environment.Exit(0);
            }

            if (!(int.TryParse(args[0], out _)))//if not a number (not an int)
            {
                PrintHelp();
                Console.WriteLine("Issue: <bits> is not a number");
                Environment.Exit(0);
            }

            var number = int.Parse(args[0]); //it's safe to parse

            if (number % 8 != 0 || number < 32) //if not a multiple of 8 or less than 32
            {
                PrintHelp();
                Console.WriteLine("Issue: " + number + "is not a multiple of 8 or is less than 32");
                Environment.Exit(0);
            }

            if (args.Length == 2) //count args was provided
            {
                if (int.TryParse(args[1], out var a)) //count args is a number?
                {
                    if (a < 1) //count is 0 or negative
                    {
                        PrintHelp();
                        Console.WriteLine("Issue: " + args[1] + " cannot be negative or 0");
                        Environment.Exit(0);
                    }
                }
                else
                {
                    PrintHelp();
                    Console.WriteLine("Issue: " + args[1] + " is not a number");
                    Environment.Exit(0);
                }
                //if reached, count is a positive int, sfe to use
            }

        }
        
        /// <summary>
        /// Print a help message.
        /// </summary>
        private static void PrintHelp()
        {
            Console.WriteLine("Usage: PrimeGen <bits> <count=1>");
            Console.WriteLine("Generate and verify prime numbers");
            Console.WriteLine("bits - \t the number of bits of the prime number, " +
                              "this must be a multiple of 8, and at least 32 bits.");
            Console.WriteLine("count - \t the number of prime numbers to generate, defaults to 1");
        }

    }
}