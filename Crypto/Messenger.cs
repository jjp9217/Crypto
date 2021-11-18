//Jesse Pingitore

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Numerics;
using System.Text.Json.Serialization;

namespace Crypto
{
  
    public class Messenger
    {
        //used for generating p and q, they must sum to 1024 
        private const int DefaultBitSize = 1024;
        
        private readonly PrimeGen _generator;
        
        //The 'e' used in RSA. May be reused, and is small for performance.
        private const int E = 65537;

        //Locations of webserver. This application requires a server to function beyond keygen.
        private const string ServerUrl = "http://kayrun.cs.rit.edu:5000/";

        private readonly HttpClient _client;


        public Messenger(int bitSize = DefaultBitSize)
        {
            this._generator = new PrimeGen(DefaultBitSize);
            this._client = new HttpClient();
        }

        

        public static void Main(string[] args)
        {
            Messenger msgr = new Messenger();
            msgr.Rsa();
            
            //msgr.ParseArguments(args); //Send down execution path with string array


            msgr.GetKey("");
        }
        
        

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keySize">Optional change to the key's bit length.</param>
        public void KeyGen(int keySize=DefaultBitSize)
        {
            if (keySize != DefaultBitSize)//if we need to adjust the bit-length...
            {
                if (!ChangeBitLength(keySize))//ensure that transition is smooth
                {
                    Console.Error.WriteLine("Error: <keySize> must be greater than or equal to 32," +
                                            "and a multiple of 8.");//it was not, halt program
                    Environment.Exit(-1);
                }
            }
                
            Rsa();

        }
        
        public void GetMsg(string email){}
        
        public void SendMsg(string email, string plaintext){}

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="email"></param>
        public async void GetKey(string email)
        {
            HttpResponseMessage response = await _client.GetAsync("http://kayrun.cs.rit.edu:5000/Key/jsb@cs.rit.edu");

            var content = response.Content;
            


        }
        
        public void SendKey(string email){}
        
        
        
        
        

        public void ParseArguments(string[] args)
        {
            if (args.Length == 0)
            {
                Console.Error.WriteLine("Error: Arguments must be provided.");
                PrintHelp();
            }

            switch (args[0])//TODO convert to enum
            {
                case "keyGen":
                    if (args.Length != 2)
                    {
                        Console.Error.WriteLine("Error: <keygen> requires an argument <keySize>");
                        return;
                    }
                    else KeyGen(Convert.ToInt32(args[1]));
                  
                    break;
                
                case "sendKey":
                    break;
                case "getKey":
                    break;
                case "sendMsg":
                    break;
                case "getMsg":
                    break;
                default:
                    Console.Error.WriteLine("Error: unrecognized argument {0}", args[0]);
                    PrintHelp();
                    Environment.Exit(-1);//exit
                    break;//please the compiler
            }
        }//TODO
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        

        /// <summary>
        /// Use RSA to generate a set of keys.
        /// </summary>
        private void Rsa()
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
            
            //TODO figure out how to store these numbers, as a field or as return vals


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
        
        /// <summary>
        /// Wrapper for PrimeGen's ChangeBitLength method.
        /// </summary>
        /// <param name="newBitLength">The new bit length. Must be greater than/equal tp 32, and a multiple of 8</param>
        /// <returns>Was the change successful?</returns>
        private Boolean ChangeBitLength(int newBitLength)
        {
            return _generator.ChangeBitLength(newBitLength);
        }
        
        /// <summary>
        /// Print a help message. TODO customize msg
        /// </summary>
        private static void PrintHelp(){
            Console.WriteLine("Usage: dotnet run <option> <option-specific args>");
            Console.WriteLine("<keygen>: \t ");
            Console.WriteLine("<sendKey>: \t");
            Console.WriteLine("<getKey>: \t");
            Console.WriteLine("<sendMsg>: \t");
            Console.WriteLine("<getMsg>: \t");
        }
    }
}