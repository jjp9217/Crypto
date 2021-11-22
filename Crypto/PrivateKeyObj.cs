//Jesse Pingitore
using System.Collections.Generic;

namespace Crypto
{
    /// <summary>
    /// A version of a key designed to hold a list of emails, rather than just one email.
    /// </summary>
    public class PrivateKeyObj : KeyObj
    {
        public List<string> emailList { get; set; }
        public PrivateKeyObj(string email, string key) : base(email,key)
        {
            this.emailList = new List<string>();
            if(email != null) emailList.Add(email);
            this.key = key;
        }

        public static PrivateKeyObj ConvertToPrivateKeyObj(KeyObj k)
        {
            return new PrivateKeyObj(k.email, k.key);
        }
    }
}