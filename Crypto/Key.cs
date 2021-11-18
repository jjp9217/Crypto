//Jesse Pingitore

using System.Buffers.Text;

namespace Crypto
{
    public class Key
    {
        public string Email { get; set; }
        public string B64Key; 

        //The value must only be updated by a byte array
        public void SetB64Key(byte[] value)
        {
            this.B64Key = System.Convert.ToBase64String(value);
        }

        public Key(string email, byte[] b64Key)
        {
            this.Email = email;
            this.B64Key = System.Convert.ToBase64String(b64Key);
        }
    }
}