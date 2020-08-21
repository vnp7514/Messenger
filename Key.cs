/**
 * File: Key.cs
 * Author: Van Pham  vnp7514@rit.edu
 * Description: These are the structures of the public key and the private key.
 * There is also the structure of the message.
 */
using System;
using System.Collections.Generic;
using System.Text;

namespace Messenger
{
    internal class PublicKey
    {
        public string email { get; set; }
        public string key { get; set; }
    }

    internal class PrivateKey
    {
        public List<string> email { get; set; }
        public string key { get; set; }
    }

    internal class Message
    {
        public string email { get; set; }
        public string content { get; set; }
    }
}
