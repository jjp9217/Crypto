//Jesse Pingitore

using System;
using System.Buffers.Text;
using System.Text.Json.Serialization;
using Microsoft.VisualBasic;

namespace Crypto
{
    public class KeyObj
    {
        public string email { get; set; }
        public string key { get; set; } //Really, this is a JSON friendly way of holding a byte array.

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