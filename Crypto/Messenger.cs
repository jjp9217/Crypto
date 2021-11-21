//Jesse Pingitore

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;


namespace Crypto
{
  
    public class Messenger
    {
        //used for generating p and q, they must sum to 1024 
        private const int DefaultBitSize = 1024;
        
        //The 'e' used in RSA. May be reused, and is small for performance.
        private const int E = 65537;
        
        //Avoid magic strings when possible.
        private const string PrivateKeyName = "private.key";
        private const string PublicKeyName = "public.key";

        //Locations of webserver. This application requires a server to function beyond keygen.
        private const string ServerUrl = "http://kayrun.cs.rit.edu:5000/";

        private readonly HttpClient _client;
        private readonly PrimeGen _generator;

        public Messenger(int bitSize = DefaultBitSize)
        {
            this._generator = new PrimeGen(DefaultBitSize);
            this._client = new HttpClient();
     
        }
        
        public static void Main(string[] args)
        {
            Messenger msgr = new Messenger();
           
            
            //msgr.ParseArguments(args); //Send down execution path with string array


            //msgr.GetKey("jsb@cs.rit.edu");
            //msgr.KeyGen();
            msgr.SendKey("jjp@cs.rit.edu");
    
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
                                            "and a multiple of 8.");//it was not, so halt execution
                    Environment.Exit(-1);
                }
            }
                
            BigInteger[] values = Rsa();
            
            //make public key
            KeyObj publicKey = ConstructKey(E, values[2]);
            
            //make private key
            KeyObj privateKey = ConstructKey(values[1], values[2]);
            
            //Write both keys to file

            var pubString = JsonSerializer.Serialize(publicKey);
            var prvString = JsonSerializer.Serialize(privateKey);
            
            File.WriteAllText(PrivateKeyName, prvString);
            File.WriteAllText(PublicKeyName, pubString);
            
            Console.WriteLine("Successfully generated keys, and saved to file.");
        }

        /// <summary>
        /// Use RSA to generate the components for the keys.
        /// The public key will use values E and N, and the private key will use values d and n.
        /// </summary>
        /// <returns>Array of [E,d,n]</returns>
        private BigInteger[] Rsa()
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

            BigInteger[] vals = {E,d,n};
            return vals;

        }

        /// <summary>
        /// This method takes in an element (E or D) and creates a key from it.
        /// The element and nonce are presumed to be generated properly.
        /// </summary>
        /// <param name="el">The element to use. Either public E or secret D</param>
        /// <param name="n">The nonce.</param>
        /// <returns>The constructed Key Object.</returns>
        private KeyObj ConstructKey(BigInteger el, BigInteger n)
        {
           
            var elBits = el.ToByteArray(); // This methods provides a LITTLE ENDIAN array, which is what we what.
            var nBits = n.ToByteArray(); // E and N are represented as LE, whereas their bytecounts e/n are BE.
            
            //Now, construct the bitcounts

            var elLen = elBits.Length;
            var nLen = nBits.Length;
            
            //Now, construct the byte Array

            byte[] key = new byte[4 + elLen + 4 + nLen];// 4 bytes for the size elements, and space for E and N
            
            //Turn eLen and nLen into bytes (already big endian)
            byte[] eLenBytes = BitConverter.GetBytes(elLen);
            byte[] nLenBytes = BitConverter.GetBytes(nLen);

            // Populate the key Array
            Array.Copy(eLenBytes,key,4);//add the length element at the start (0 to 4)
            Array.Copy(elBits,0,key,4,elLen);
            Array.Copy(nLenBytes,0,key,elLen+4,4);
            Array.Copy(nBits,0,key,elLen+4+4,nLen);

            //The key is ready to construct

            return new KeyObj(null, key);//Email is left as null initially
        }
        
        public void GetMsg(string email){}
        
        public void SendMsg(string email, string plaintext){}

        /// <summary>
        /// This method will retrieve a PUBLIC key from the message server.
        /// If successful in fetching, it will write the key to the filesystem where this project is executed.
        /// If the fetched key already exists, it will be overwritten.
        /// </summary>
        /// <param name="email">The email of the user who we want to fetch a public key from</param>
        public async void GetKey(string email)
        {
            var request =  _client.GetAsync(ServerUrl + "Key/" + email);
            var response = request.Result;

            if (!response.IsSuccessStatusCode)
            {
                switch (response.StatusCode)
                {
                    case HttpStatusCode.NotFound:
                        Console.Error.WriteLine("Error: Server could not find a key associated with '{0}'",
                            email);
                        break;

                    default:
                        Console.Error.WriteLine("Error: Server returned error '{0}', key cannot be fetched.",
                            response.StatusCode);
                        break;
                }
            }
            
            string content = await response.Content.ReadAsStringAsync();

            try
            {
                JsonSerializer.Deserialize<KeyObj>(content);
            }
            catch (JsonException)
            {
                await Console.Error.WriteLineAsync("Error: The key received from the server is corrupted. Aborting operation.");
                return; //Don't write a broken key
            }
            
            await File.WriteAllTextAsync(email, content);
        }

        /// <summary>
        /// This method will push the public key to the server. 
        /// </summary>
        public void SendKey(string email)
        {
            //first, see if the public key exists
            try
            {
                string strKey = File.ReadAllText(PublicKeyName);
                
                //next add the email to the pubkey

                KeyObj pubKey = JsonSerializer.Deserialize<KeyObj>(strKey);
                if (pubKey != null)
                {
                    pubKey.Email = email;
                    
                    //next, push the key to server
                    strKey = JsonSerializer.Serialize(pubKey);
                    JsonContent keyContent = JsonContent.Create(strKey);

                    var putRequest = _client.PutAsync(ServerUrl, keyContent);
                    var response = putRequest.Result;
                    
                    //next, check the return code to sure nothing went wrong
                    
                    //TODO check

                    //finally, add the email string to the private key so we know whose public key it matches
                }
                else
                {
                    Console.Error.WriteLine("Error: The public key in the directory this project was " +
                                            "executed in cannot be parsed, check the key for corruption.");
                }
               
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine("Error: {0} does not exist in the directory this project was executed in.",
                    PublicKeyName);
            }
            
        }
        
        
        
        
        

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
                    }
                    else KeyGen(Convert.ToInt32(args[1]));
                  
                    break;
                
                case "sendKey":
                    break;
                case "getKey":
                    if (args.Length != 2)
                    {
                        Console.Error.WriteLine("Error: <getKey> requires an argument <email>");
                    }
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
            Console.WriteLine("<keyGen>: <keySize>\t ");
            Console.WriteLine("<sendKey>: \t");
            Console.WriteLine("<getKey>: <email>\t");
            Console.WriteLine("<sendMsg>: \t");
            Console.WriteLine("<getMsg>: \t");
        }
    }
}