/**
 * File: Messenger.cs
 * Author: Van Pham  vnp7514@rit.edu
 * Description: This class handles the RSA encryption and decryption.
 * It also handles the messaging.
 */
using Newtonsoft.Json;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Messenger
{
    class Messenger
    {
        // The client side to retrieve/send data from/to the server 
        private static readonly HttpClient client = new HttpClient();

        // The URL to the server
        private static string server = "http://kayrun.cs.rit.edu:5000";

        /**
         * This will generate a keypair of size 'keysize' bits (public and private key)
         * and store them locally on the disk (in files called 'public.key' and 'private.key'
         * respectively).
         */
        public void KeyGen(Int64 keysize)
        {
            if (keysize < 64)
            {
                throw new Exception("keysize must be at least 64!");
            }
            else if ((keysize % 8) != 0)
            {
                throw new Exception("keysize must be a multiple of 8.");
            }
            else
            {
                Int64 psize = ((keysize / 8) / 2) * 8;
                Int64 qsize = keysize - psize;
                BigInteger p = getPrimeNumber(psize);
                BigInteger q = getPrimeNumber(qsize);
                BigInteger N = p * q;
                BigInteger r = (p - 1) * (q - 1);
                BigInteger E = 65537;
                BigInteger D = modInverse(E, r);
                savingPublicKey(E, N);
                savingPrivateKey(D, N);
            }
        }

        /**
         * Create a public key with the provide E and N. Then save it to 
         * a file named 'public.key'
         * 
         * Param:
         *      E   E in RSA Algorithm
         *      N   N in RSA Algorithm
         */
        private void savingPublicKey(BigInteger E, BigInteger N)
        {
            int sizeOfE = E.GetByteCount();
            int sizeOfN = N.GetByteCount();
            // initializing the byte array for the public key
            var publicKey = new byte[4 + sizeOfE + 4 + sizeOfN];
            var temp = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(temp, sizeOfE);
            // Copy the size of E to the key
            temp.CopyTo(publicKey, 0);

            // Copy E to the key
            E.ToByteArray().CopyTo(publicKey, 4);

            temp = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(temp, sizeOfN);
            // Copy size of N to the key
            temp.CopyTo(publicKey, 4 + sizeOfE);

            // Copy N to the key
            N.ToByteArray().CopyTo(publicKey, 4 + sizeOfE + 4);

            string json = createPublicKeyJson(publicKey);
            writePublicKey(json);
        }

        /**
         * This will create a JSON representation of the PublicKey class
         * Param:
         *      Key   the key to be inserted to the PublicKey class
         *      
         * Return:
         *      A Json representation
         */
        private string createPublicKeyJson(byte[] Key)
        {
            var b64PublicKey = Convert.ToBase64String(Key);
            var pKey = new PublicKey();
            pKey.email = null;
            pKey.key = b64PublicKey;
            return JsonConvert.SerializeObject(pKey);
        }

        /**
         * This saves the PublicKey structure to a file named 'public.key'
         * Param:
         *       json the PublicKey structure JSON representation
         */
        private void writePublicKey(string json)
        {
            try
            {
                var path = Directory.GetCurrentDirectory()+"/public.key";
                var fi = new FileInfo(path);
                if (fi.Exists)
                {
                    fi.Delete();
                }
                var ws = fi.CreateText();
                ws.Write(json);
                ws.Dispose();
            } 
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Cannot access the local directory" +
                    "to save the public key");
                System.Environment.Exit(1);
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("the byte array is null.");
                System.Environment.Exit(1);
            }
            catch (Exception)
            {
                Console.WriteLine("Unable to write the public key to the file.");
                System.Environment.Exit(1);
            }
        }

        /**
         * Create a private key with the provide D and N. Then save it to 
         * a file named 'private.key'
         * 
         * Param:
         *      D   D in RSA Algorithm
         *      N   N in RSA Algorithm
         */
        private void savingPrivateKey(BigInteger D, BigInteger N)
        {
            int sizeOfD = D.GetByteCount();
            int sizeOfN = N.GetByteCount();
            // initializing the byte array for the public key
            var privateKey = new byte[4 + sizeOfD + 4 + sizeOfN];
            var temp = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(temp, sizeOfD);
            // Copy the size of E to the key
            temp.CopyTo(privateKey, 0);

            // Copy E to the key
            D.ToByteArray().CopyTo(privateKey, 4);

            temp = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(temp, sizeOfN);
            // Copy size of N to the key
            temp.CopyTo(privateKey, 4 + sizeOfD);

            // Cop N to the key
            N.ToByteArray().CopyTo(privateKey, 4 + sizeOfD + 4);

            string json = createPrivateKeyJson(privateKey);
            writePrivateKey(json);
        }

        /**
         * This will create a JSON representation of the PrivateKey class
         * Param:
         *      Key   the key to be inserted to the PrivateKey class
         *      
         * Return:
         *      A Json representation
         */
        private string createPrivateKeyJson(byte[] Key)
        {
            var b64PrivateKey = Convert.ToBase64String(Key);
            var pKey = new PrivateKey();
            pKey.email = null;
            pKey.key = b64PrivateKey;
            return JsonConvert.SerializeObject(pKey);
        }


        /**
         * This saves the PrivateKey structure to a file named 'private.key'
         * Param:
         *      privateKey the new JSON Private Key representation
         */
        private void writePrivateKey(string privateKey)
        {
            try
            {
                var path = Directory.GetCurrentDirectory() + "/private.key";
                var fi = new FileInfo(path);
                if (fi.Exists)
                {
                    fi.Delete();
                }
                var ws = fi.CreateText();
                ws.Write(privateKey);
                ws.Dispose();
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Cannot access the local directory" +
                    "to save the private key");
                System.Environment.Exit(1);
            }
            catch (ArgumentNullException)
            {
                Console.WriteLine("the byte array is null.");
                System.Environment.Exit(1);
            }
            catch (Exception)
            {
                Console.WriteLine("Unable to write the private key to the file.");
                System.Environment.Exit(1);
            }
        }

        /**
         * Initialize a PrimGen instance with the specified size
         * then generate a prime number. Finally, terminate the instance.
         * 
         * Parameters:
         *      size    the size of the prime number to be generated
         *      
         * Return a BigInteger that is a prime number
         */
        private BigInteger getPrimeNumber(Int64 size)
        {
            PrimeGen primeGen = new PrimeGen(size);
            BigInteger result = primeGen.generate();
            primeGen.terminate();
            return result;
        }

        /**
         * This option sends the public key that was generated in the 
         * keyGen phase and to the server. The server will then register 
         * this email address as a valid receiver of messages. The private 
         * key will remain locally, though the email address
         * that was given should be added to the private key for later 
         * validation. If the server already has a key for this user, 
         * it will be overwritten.
         */
        public async Task<bool> SendKey(string email)
        {
            try
            {
                var jsonObject = addEmail(email);
                var content = new StringContent(jsonObject.ToString(), Encoding.UTF8, 
                    "application/json");
                var Uri = server + "/Key/" + email;
                var msg = await client.PutAsync(Uri, content);
                msg.EnsureSuccessStatusCode();
                Console.WriteLine("Key saved");
                client.Dispose();
            } catch (Exception e)
            {
                Console.WriteLine(e.Message);
                System.Environment.Exit(1);
            }
            return true;
        }

        /**
         * This will add the specified email to the local private.key and 
         * public.key files. Then return the json string of the public.key
         * 
         * Param:
         *      email the email
         *  
         * Return: json representation of the PublicKey
         */
        private string addEmail(string email)
        {
            addEmailtoPrivateKey(email);
            var json = addEmailtoPublicKey(email);
            if (json == null)
            {
                Console.WriteLine("Unable to add the new email to public.key");
                System.Environment.Exit(1);
            }
            return json;
        }

        /**
         * Retrieve the json from the local file public.key then
         * deserialize it to obtain the PublicKey instance. Add 
         * the specified email to the instance then overwrite the old
         * public.key with the new instance.
         * 
         * Param: 
         *      email  the email to be added
         *      
         * Return:
         *      the Json representation of the new PublicKey instance
         *      null if anything fails.
         */
        private string addEmailtoPublicKey(string email)
        {
            try
            {
                var path = Directory.GetCurrentDirectory() + "/public.key";
                var fi = new FileInfo(path);
                if (!fi.Exists)
                {
                    throw new Exception("public.key is not found in local directory");
                }
                var sr = fi.OpenText();
                var jsonObject = sr.ReadToEnd();
                sr.Dispose();
                var pKey = JsonConvert.DeserializeObject<PublicKey>(jsonObject);
                pKey.email = email;

                string json = JsonConvert.SerializeObject(pKey);
                writePublicKey(json);
                return json;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                System.Environment.Exit(1);
            }
            return null;
        }

        /**
         * Retrieve the json from the local file private.key then
         * deserialize it to obtain the PrivateKey instance. Add 
         * the specified email to the instance then overwrite the old
         * private.key with the new instance.
         * 
         * Param: 
         *      email  the email to be added
         *      
         */
        private void addEmailtoPrivateKey(string email)
        {
            try
            {
                var path = Directory.GetCurrentDirectory() + "/private.key";
                var fi = new FileInfo(path);
                if (!fi.Exists)
                {
                    throw new Exception("private.key is not found in local directory");
                }
                var sr = fi.OpenText();
                var jsonObject = sr.ReadToEnd();
                sr.Dispose();
                var pKey = JsonConvert.DeserializeObject<PrivateKey>(jsonObject);
                if (pKey.email == null)
                {
                    pKey.email = new List<string> { email };
                }
                else
                {
                    pKey.email.Add(email);
                }

                writePrivateKey(JsonConvert.SerializeObject(pKey));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                System.Environment.Exit(1);
            }
        }

        /**
         * This will retrieve public key for a particular user (not 
         * usually yourself). You will need this key to encode messages
         * for a particular user. You should store it on the local 
         * filesystem as  <email>.key. 
         * (ie, if I issue getKey jeremy.brown@rit.edu
         * it should write it locally as jeremy.brown@rit.edu.key 
         * so that you can have multiplekeys stored and not overwrite your 
         * local keys. You should store this key the same way you 
         * store your own public key. This is convinient as this is 
         * the format you get from the server.
         */
        public async Task<bool> GetKey(string email)
        {
            try
            {
                var connect = client.GetAsync(server + "/Key/" + email);
                var msg = await connect;
                msg.EnsureSuccessStatusCode();
                var msgTask = msg.Content.ReadAsStringAsync();
                var msgBody = await msgTask;
                var path = Directory.GetCurrentDirectory() + "/" + email + ".key";
                var fi = new FileInfo(path);
                if (fi.Exists)
                {
                    fi.Delete();
                }
                var sw = fi.CreateText();
                sw.Write(msgBody);
                sw.Dispose();
                client.Dispose();
            } catch (Exception e)
            {
                Console.WriteLine(e.Message+". This is an error.");
                System.Environment.Exit(1);
            }
            return true;
        }

        /**
         * This will take a plaintext message, encrypt it using the
         * public key of the person you are sending it to, and then
         * base64 encode it before sending it to the server
         * 
         * Param:
         *       email      the email to send the ciphertext to
         *       plaintext  the text to be encrypted
         */
        public async Task<bool> SendMsg(string email, string plaintext)
        {
            try
            {
                var pubK = getPublicKey(email);
                if (pubK == null)
                {
                    throw new Exception("Key does not exist for " + email);
                }
                var msg = encrypt(pubK, plaintext);
                var jsonObject = JsonConvert.SerializeObject(msg);
                var content = new StringContent(jsonObject.ToString(), Encoding.UTF8,
                        "application/json");
                var Uri = server + "/Message/" + email;
                var result = await client.PutAsync(Uri, content);
                result.EnsureSuccessStatusCode();
                Console.WriteLine("Message written");
                client.Dispose();
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                System.Environment.Exit(1);
            }
            return true;
        }

        /**
         * Return the PrivateKey instance stored in the local system
         */
        private PrivateKey getPrivateKey()
        {
            try
            {
                var fi = new FileInfo(Directory.GetCurrentDirectory() + "/private.key");
                if (!fi.Exists)
                {
                    throw new Exception("private key was not generated!");
                }
                var sr = fi.OpenText();
                var json = sr.ReadToEnd();
                sr.Dispose();
                return JsonConvert.DeserializeObject<PrivateKey>(json);
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                System.Environment.Exit(1);
            }
            return null;
        }

        /**
         * Return the PublicKey instance associated with the provided email
         * from the local system
         * Param:
         *      email the email
         * 
         */
        private PublicKey getPublicKey(string email)
        {
            try
            {
                var fi = new FileInfo(Directory.GetCurrentDirectory() + "/" + email + ".key");
                if (!fi.Exists)
                {
                    Console.WriteLine("Key does not exist for " + email);
                    Console.WriteLine("It must be downloaded first.");
                    throw new Exception();
                }
                var sr = fi.OpenText();
                var json = sr.ReadToEnd();
                sr.Dispose();
                return JsonConvert.DeserializeObject<PublicKey>(json);
            } 
            catch
            {
                System.Environment.Exit(1);
            }
            return null;
        }

        /**
         * Encrypt the plaintext using the info from PublicKey instance
         * Param:
         *      pKey      PublicKey instance
         *      plaintext the text to be encrypted
         *      
         * Return:
         *      A Message instance with the same email as PublicKey instance
         *      and the content of it is the encrypted message
         */
        private Message encrypt(PublicKey pKey, string plaintext)
        {
            var pKeyByteArray = Convert.FromBase64String(pKey.key);

            var sizeOfE = BinaryPrimitives.ReadInt32BigEndian(
                getSegment(0, 4, pKeyByteArray));
            var E = new BigInteger(getSegment(4, 4 + sizeOfE, pKeyByteArray));

            var sizeOfN = BinaryPrimitives.ReadInt32BigEndian(
                getSegment(4 + sizeOfE, 4 + 4 + sizeOfE, pKeyByteArray));
            var N = new BigInteger(
                getSegment(4 + 4 + sizeOfE, pKeyByteArray.Length, pKeyByteArray));
            var P = new BigInteger(Encoding.UTF8.GetBytes(plaintext));
            var C = BigInteger.ModPow(P, E, N);
            var content = Convert.ToBase64String(C.ToByteArray());
            var msg = new Message();
            msg.content = content;
            msg.email = pKey.email;
            return msg;
        }

        /**
         * Get a segment of the provided byte array starting from the index start
         * to the index end
         * Param:
         *      org    the orginal array
         *      start  the starting index
         *      end    exclusive end
         * Return:
         *      a segment of the provide array
         *      
         * Example:
         *      getSegment(0, 3, [1,1,1,4]) = [1, 1, 1]
         *      getSegment(1, 2, [1,2,3,4]) = [2]
         * 
         */
        private byte[] getSegment(int start, int end, byte[] org)
        {
            if (start < 0 || end < 0)
            {
                return null;
            }
            if (start > end)
            {
                var temp = start;
                start = end;
                end = temp;
            }
            var result = new byte[end - start];
            int a = 0; // index count for result
            for (int i = 0; i < org.Length; i++)
            {
                if (start<= i && i < end)
                {
                    result[a] = org[i];
                    a++;
                }
            }
            return result;
        }

        /**
         * This will retrieve a message for a particular user, while 
         * it is possible to download messages for any user, you will
         * only be able to decode messages for which you have the private
         * key.
         */
        public async Task<bool> GetMsg(string email)
        {
            try
            {
                var priKey = getPrivateKey();
                if (priKey == null)
                {
                    throw new Exception("you need to call sendKey <email> to" +
                        "register your email on the server.");
                }
                if (!priKey.email.Contains(email))
                {
                    throw new Exception("Message cannot be decode because " +
                        "you do not have a private key for the requested email.");
                }
                var result = await client.GetAsync(server + "/Message/" + email);
                result.EnsureSuccessStatusCode();
                var json = await result.Content.ReadAsStringAsync();
                var msg = JsonConvert.DeserializeObject<Message>(json);
                if (msg == null)
                {
                    throw new Exception("No Message was sent!");
                }
                Console.WriteLine(decrypt(priKey, msg));
                client.Dispose();
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
                System.Environment.Exit(1);
            }
            return true;
        }

        /**
         * Decrypt the ciphertext using info from the PrivateKey instance
         * Param:
         *      pKey      PrivateKey instance
         *      msg       The instance with the encrypted message
         *      
         * Return:
         *      the plaintext
         *      null if the email in pKey does not match the email in msg.
         *          The ciphertext is not for us
         */
        private string decrypt(PrivateKey pKey, Message msg)
        {
            if (!pKey.email.Contains(msg.email))
            {
                return null;
            }
            var pKeyByteArray = Convert.FromBase64String(pKey.key);

            var sizeOfD = BinaryPrimitives.ReadInt32BigEndian(
                getSegment(0, 4, pKeyByteArray));
            var D = new BigInteger(getSegment(4, 4 + sizeOfD, pKeyByteArray));

            var sizeOfN = BinaryPrimitives.ReadInt32BigEndian(
                getSegment(4 + sizeOfD, 4 + 4 + sizeOfD, pKeyByteArray));
            var N = new BigInteger(
                getSegment(4 + 4 + sizeOfD, pKeyByteArray.Length, pKeyByteArray));
            var C = new BigInteger(Convert.FromBase64String(msg.content));
            var P = BigInteger.ModPow(C, D, N);
            return Encoding.UTF8.GetString(P.ToByteArray());
        }

        static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1; 
            while (a > 0) 
            { 
                BigInteger t = i / a, x = a; 
                a = i % x; 
                i = x; 
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) 
                v = (v + n) % n;
            return v;
        }
    }
}
