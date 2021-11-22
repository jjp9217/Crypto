//Jesse Pingitore

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Text;
using System.Text.Json;


namespace Crypto
{
    /// <summary>
    /// A basic messenger service. Generates an RSA keypair, and sends over HTTP to a partner server.
    /// This program presumes that the architecture of the running computer is Big Endian.
    /// </summary>
    public class Messenger
    {
        //used for generating p and q, they must sum to 1024 
        private const int DefaultBitSize = 1024;
        
        //The 'e' used in RSA. May be reused, and is small for performance.
        private const int E = 65537;
        
        //This constant governs how many bytes we store for the size indicator of el/Nonce, MUST BE 4 -> 32 bit int
        private const int AllocatedBytes = 4;
        
        //Avoid magic strings when possible.
        private const string PrivateKeyName = "private.key";
        private const string PublicKeyName = "public.key";
        private const String KeyFileExtension = ".key";

        //Locations of webserver and URL options. This application requires a server to function beyond keygen.
        private const string ServerUrl = "http://kayrun.cs.rit.edu:5000/";
        private const string KeyExtension = "Key/";
        private const String MsgExtension = "Message/";
        
        

        private readonly HttpClient _client;
        private readonly PrimeGen _generator;

        public Messenger(int bitSize = DefaultBitSize)
        {
            this._generator = new PrimeGen(bitSize);
            this._client = new HttpClient();
     
        }
        
        public static void Main(string[] args)
        {
            Messenger msgr = new Messenger();
            //msgr.ParseArguments(args); //Send down execution path with string array

            
            //msgr.KeyGen();
            // msgr.SendKey("jjp9217@cs.rit.edu");
            // msgr.GetKey("jjp9217@cs.rit.edu");
            //
            //
            msgr.SendMsg("jjp9217@cs.rit.edu","bababoi");
            
            msgr.GetMsg("jjp9217@cs.rit.edu");
            
    
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

            byte[] key = new byte[AllocatedBytes + elLen + AllocatedBytes + nLen];
            // 4 bytes for the size elements, and space for E and N
            
            //Turn eLen and nLen into bytes 
            byte[] eLenBytes = BitConverter.GetBytes(elLen);
            byte[] nLenBytes = BitConverter.GetBytes(nLen);
            
            //Turn the arrays into Big Endian form (x86 is little endian)
            Array.Reverse(eLenBytes);
            Array.Reverse(nLenBytes);

            // Populate the key Array
            Array.Copy(eLenBytes,key,AllocatedBytes);//add the length element at the start (0 to 4)
            Array.Copy(elBits,0,key,AllocatedBytes,elLen);
            Array.Copy(nLenBytes,0,key,elLen+AllocatedBytes,AllocatedBytes);
            Array.Copy(nBits,0,key,elLen+AllocatedBytes+AllocatedBytes,nLen);

            //The key is ready to construct

            return new KeyObj(null, key);//Email is left as null initially
        }

        /// <summary>
        /// The inverse operator of Rsa(). Will take in a formed key (as byte[]), and return it's element and nonce.
        /// </summary>
        /// <param name="key">The key to extract the element and nonce from. Must be in byte-array form.</param>
        /// <returns>The element, nonce, and their sizes in form [el,N,elLen,NLen]</returns>
        private BigInteger[] ExtractKey(byte[] key)
        {
            BigInteger[] vals = new BigInteger[4];
            
            //first, read the first number of bytes to know the size of the next element
            byte[] elLengthBytes = new byte[AllocatedBytes];
            
            Array.Copy(key, elLengthBytes, AllocatedBytes);
            
            Array.Reverse(elLengthBytes); //We must convert it to Little Endian for it to work on x86

            int elLen = BitConverter.ToInt32(elLengthBytes, 0); //interprets as LE
            
            //now we know the length of the element, so rip it out of the array

            byte[] el = new byte[elLen]; 
            
            Array.Copy(key, AllocatedBytes, el,0,elLen);

            vals[0] = new BigInteger(el);

            //and do the same for Nonce 

            byte[] nLenB = new byte[AllocatedBytes];
            Array.Copy(key, elLen + AllocatedBytes, 
                nLenB, 0, AllocatedBytes);
            Array.Reverse(nLenB);
            int nLen = BitConverter.ToInt32(nLenB, 0);
            byte[] n = new byte[nLen];
            Array.Copy(key, elLen + AllocatedBytes + AllocatedBytes, n, 0, nLen);

            vals[1] = new BigInteger(n);
            
            //and add the sizes for message verification
            vals[2] = new BigInteger(elLen);
            vals[3] = new BigInteger(nLen);
            
            return vals;
        }

        /// <summary>
        /// Get a message from the server from the user provided in the email argument. We must already possess this
        /// user's private key in order to decrypt and read the message.
        /// </summary>
        /// <param name="email">The email of the user whose ciphered message we are fetching</param>
        public void GetMsg(string email)
        {
            // First, see if this user's private key exists
            try
            {
                string strKey = File.ReadAllText(PrivateKeyName);
                //Next make sure the email appears in the private key (it was written by us!)

                KeyObj pvtKey = JsonSerializer.Deserialize<KeyObj>(strKey);
                if (pvtKey == null)
                {
                    Console.Error.WriteLine("Error: Private key is null, check for corruption.");
                    return;
                }

                if (!pvtKey.email.Contains(email))
                {
                    Console.Error.WriteLine("Error: This private key does not correspond to the email '{0}'",
                        email);
                    return;
                }//else, we can proceed!
                //fetch the message from the server
                var sendTo = ServerUrl + MsgExtension + email;
                
                var request =  _client.GetAsync(sendTo);
                var response = request.Result;
                
                if (!response.IsSuccessStatusCode) // Inform user of fetch failure if required
                {
                    switch (response.StatusCode)
                    {
                        case HttpStatusCode.NotFound:
                            Console.Error.WriteLine("Error: Server could not find a message associated with '{0}'",
                                email);
                            break;

                        default:
                            Console.Error.WriteLine("Error: Server returned error '{0}', message cannot be fetched.",
                                response.StatusCode);
                            break;
                    }
                    return;
                }//else, we have the message! 
                
                var contentTask = response.Content.ReadAsStringAsync();
                var content = contentTask.Result;

                try
                {
                    Message msg = JsonSerializer.Deserialize<Message>(content);
                    // We have an intact message, now get the ciphertext out

                    if (msg == null)
                    { 
                        Console.Error.WriteLine("Error occured when trying to process JSON, the message was corrupted.");
                        return;
                    }
                    
                    var ciphertext = msg.content;

                    if (ciphertext == null) //Verify...
                    {
                        Console.Error.WriteLine("Error: The message content is null, the message is corrupted.");
                        return;
                    }
                    
                    // Turn into a byte array
                    var cipherAsBytes = Convert.FromBase64String(ciphertext);
                    
                    // Turn into a number
                    var cipherAsBigInt = new BigInteger(cipherAsBytes);
                    
                    // Now, ready the key.

                    byte[] trueKey = pvtKey.GetKeyAsBytes();
                    BigInteger[] values = ExtractKey(trueKey);
                    var d = values[0];
                    var n = values[1];
                    
                    if (cipherAsBytes.Length >= values[2] + values[3]) // No messages longer than the key allowed
                    {
                        Console.Error.WriteLine("Error: The length of the received ciphertext (len = {0}) exceeds the keySize {1}." +
                                                "\n The ciphertext cannot be decrypted.",
                            cipherAsBytes.Length, (values[2] + values[3]));
                        return; //exit
                    }
                    
                    // Crack it.
                    var plainAsBigInt = BigInteger.ModPow(d, n, cipherAsBigInt);
                    
                    // Turn it into bytes...
                    var plainAsBytes = plainAsBigInt.ToByteArray();
                    
                    // ... and turn it into plaintext

                    var plaintext = Encoding.UTF8.GetString(plainAsBytes);
                    
                    Console.WriteLine(plaintext); // Right as rain.
                }
                catch (JsonException)
                {
                    Console.Error.WriteLine("Error occured when trying to process JSON, the message was corrupted.");

                }
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine("Error: {0} does not exist in the directory this project was executed in.",
                    PrivateKeyName);
            }
            catch (JsonException)
            {
                Console.Error.WriteLine("Error occured when trying to process JSON, the key was corrupted.");
            }
            
        }

        /// <summary>
        /// Encrypt a message with a public key, and send it to the server.
        /// </summary>
        /// <param name="email"></param>
        /// <param name="plaintext"></param>
        public void SendMsg(string email, string plaintext)
        {
            //first, ensure we have a key matching this email
            try
            {
                string pubStr = File.ReadAllText(email + KeyFileExtension);
                
                //next, construct it into an object

                KeyObj key = JsonSerializer.Deserialize<KeyObj>(pubStr);

                if (key == null)
                {
                    Console.Error.WriteLine("Error: The public key for '{0}' cannot be verified as a valid key.", email);
                    return;
                }
                
                //next, get the b64 string and turn it into a byte array

                byte[] trueKey = key.GetKeyAsBytes();
                
                //next we need to perform an encoding. strip out E and N from the byte array

                BigInteger[] values = ExtractKey(trueKey);
                var e = values[0];
                var n = values[1];
                
                //verify that we can encode the message, if the bit length of e+n < message we cannot send it

                var plainBytes = Encoding.UTF8.GetBytes(plaintext);
                if (plainBytes.Length >= values[2] + values[3]) // No messages longer than the key allowed
                {
                    Console.Error.WriteLine("Error: The length of message '{0}' (len = {1}) exceeds the keySize {2}." +
                                            "All messages must be smaller than the keySize. \n This may be fixed by" +
                                            " generating a new keypair with a larger keySize.", plaintext, 
                        plainBytes.Length, (values[2] + values[3]));
                    return; //exit
                }//else, we may proceed

                BigInteger plainAsBigInt = new BigInteger(plainBytes);
                
                // Do it
                BigInteger ciphered = BigInteger.ModPow(e, n, plainAsBigInt);
                
                //Turn to bytes...
                byte[] cipherAsBytes = ciphered.ToByteArray();
                
                //... and base64 encode
                string ciphertext = Convert.ToBase64String(cipherAsBytes);
                
                //Create the message, serialize it, and format it for sending
                Message msg = new Message(email, ciphertext);
                var msgStr = JsonSerializer.Serialize(msg);
                var msgContent = new StringContent(msgStr, Encoding.UTF8, "application/json");
                var sendTo = ServerUrl + MsgExtension + email;
                
                // Fire.
                var putRequest = _client.PutAsync(sendTo, msgContent);
                var response = putRequest.Result;

                // Check effect.
                switch (response.StatusCode)
                {
                    case HttpStatusCode.NotFound:
                        Console.Error.WriteLine("Error: URL not found, 404. URL may have changed from old '{0}'. Recompile " +
                                                " with correct server URL.", ServerUrl);
                        break;
                    case HttpStatusCode.OK://success cases
                        Console.WriteLine("Message written");
                        break;
                    case HttpStatusCode.NoContent:
                        Console.WriteLine("Message written");
                        break;
                    default:
                        Console.WriteLine("Received unexpected response: " + response.StatusCode);
                        break;
                }// We're done here
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine("Key does not exist for '{0}'", email);
            }
        }

        /// <summary>
        /// This method will retrieve a PUBLIC key from the message server.
        /// If successful in fetching, it will write the key to the filesystem where this project is executed.
        /// If the fetched key already exists, it will be overwritten.
        /// </summary>
        /// <param name="email">The email of the user who we want to fetch a public key from</param>
        public async void GetKey(string email)
        {
            var sendTo = ServerUrl + KeyExtension + email;
            var request =  _client.GetAsync(sendTo);
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
                await Console.Error.WriteLineAsync("Error: The key received from the server is is not a valid key. " +
                                                   "Aborting operation.");
                return; //Don't write a broken key
            }
            
            await File.WriteAllTextAsync(email + KeyFileExtension, content); 
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
                
                //next add the email to the public key
                KeyObj pubKey = JsonSerializer.Deserialize<KeyObj>(strKey);
                if (pubKey != null)
                {
                    pubKey.email = email;
                    
                    //next, push the key to server
                    strKey = JsonSerializer.Serialize(pubKey);
                    var keyContent = new StringContent(strKey, Encoding.UTF8, "application/json");  

                    var sendTo = ServerUrl + KeyExtension + email;
                    var putRequest = _client.PutAsync(sendTo, keyContent);
                    HttpResponseMessage response = putRequest.Result;
                    
                    //next, check the return code to sure nothing went wrong

                    switch (response.StatusCode)
                    {
                        case HttpStatusCode.NotFound:
                            Console.Error.WriteLine("Error: URL not found, 404. URL may have changed from old '{0}'. Recompile " +
                                                    " with correct server URL.", ServerUrl);
                            break;
                        case HttpStatusCode.OK://success cases
                            Console.WriteLine("Key saved");
                            break;
                        case HttpStatusCode.NoContent:
                            Console.WriteLine("Key saved");
                            break;
                        default:
                            Console.WriteLine("Received unexpected response: " + response.StatusCode);
                            break;
                    }

                    //finally, add the email string to the private key so we know whose public key it matches
                    strKey = File.ReadAllText(PrivateKeyName);
                    KeyObj pvtKey = JsonSerializer.Deserialize<KeyObj>(strKey);
                    if (pvtKey != null)
                    {
                        pvtKey.email = email; //TODO turn this into a list (why do we need that?)
                    }

                    var outStr = JsonSerializer.Serialize(pvtKey);
                    File.WriteAllText(PrivateKeyName, outStr);
                }
                
                else
                {
                    Console.Error.WriteLine("Error: The public key in the directory this project was " +
                                            " executed in cannot be parsed, check the key for corruption.");
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
                    if (args.Length != 2)
                    {
                        Console.Error.WriteLine("Error: <sendKey> requires an argument <email>");
                    }
                    else SendKey(args[1]);
                    break;
                case "getKey":
                    if (args.Length != 2)
                    {
                        Console.Error.WriteLine("Error: <getKey> requires an argument <email>");
                    }
                    else GetKey(args[1]);
                    break;
                case "sendMsg":
                    if (args.Length != 3)
                    {
                        Console.Error.WriteLine("Error: <sendMsg> requires arguments <email> and <message>");
                    }
                    else SendMsg(args[1],args[2]);
                    break;
                case "getMsg":
                    if (args.Length != 2)
                    {
                        Console.Error.WriteLine("Error: <getMsg> requires an argument <email>");
                    }
                    else GetMsg(args[1]);
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
        /// <param name="r">Exponent?</param>
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