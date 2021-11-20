//Jesse Pingitore

using System.Buffers.Text;
using System.Text.Json.Serialization;

namespace Crypto
{
    public class KeyObj
    {
        public string Email { get; set; }
        public string Key { get; set; }

        //The value must only be updated by a byte array
        public void SetB64Key(byte[] value)
        {
            this.Key = System.Convert.ToBase64String(value);
        }

        public KeyObj(string email, byte[] b64Key)
        {
            this.Email = email;
            this.Key = System.Convert.ToBase64String(b64Key);
        }
        
        [JsonConstructor]
        public KeyObj(string email, string key)
        {
            this.Email = email;
            this.Key = (key); //presume everything will be fine during deserialization
        }
    
    }
}