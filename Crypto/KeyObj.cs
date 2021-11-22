//Jesse Pingitore
using System;
using System.Text.Json.Serialization;

namespace Crypto
{
    /// <summary>
    /// An format for a Key. Designed for use as a JSON object.
    /// </summary>
    public class KeyObj
    {
        // The server specifically stores these with lowercase names, so we must break C# style purposely. 
        public string email { get; set; }
        public string key { get; set; } //Really, this is a JSON friendly way of encoding a byte array.

        //The value must only be updated by a byte array
        public void SetB64Key(byte[] value)
        {
            this.key = System.Convert.ToBase64String(value);
        }

        public byte[] GetKeyAsBytes()
        {
            return Convert.FromBase64String(key);
        }

        public KeyObj(string email, byte[] b64Key)
        {
            this.email = email;
            this.key = System.Convert.ToBase64String(b64Key);
        }
        
        [JsonConstructor]
        public KeyObj(string email, string key)
        {
            this.email = email;
            this.key = (key); 
            //When we use serial/deserialization, we presume we are getting an already b64 encoded string
        }
    
    }
}