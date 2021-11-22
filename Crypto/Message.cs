//Jesse Pingitore

using System;
using System.Text.Json.Serialization;

namespace Crypto
{
    /// <summary>
    /// A JSON-friendly way of transporting information associated with a user. Essentially a KeyObj with
    /// a renamed field.
    /// </summary>
    public class Message
    {
        // The server specifically stores these with lowercase names, so we must break C# style purposely. 
        public string email { get; set; }
        public string content { get; set; } //Really, this is a JSON friendly way of holding a byte array.

        //The value must only be updated by a byte array
        public void SetB64Content(byte[] value)
        {
            this.content = System.Convert.ToBase64String(value);
        }

        public byte[] GetContentKAsBytes()
        {
            return Convert.FromBase64String(content);
        }

        public Message(string email, byte[] b64Content)
        {
            this.email = email;
            this.content = System.Convert.ToBase64String(b64Content);
        }
        
        [JsonConstructor]
        public Message(string email, string content)
        {
            this.email = email;
            this.content = (content); 
            //When we use serial/deserialization, we presume we are getting an already b64 encoded string
        }
    }
}