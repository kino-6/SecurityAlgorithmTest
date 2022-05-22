using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace SecurityAlgorithmTest
{
    class MyAES : MySecurityBase
    {
        public string AesIV = @"8863d67c62113fb8";
        public string AesKey = @"2eeee02d3dc3ef6c";
        public int block_size = 128;
        public int key_size = 128;
        public PaddingMode padding = PaddingMode.Zeros;
        public CipherMode mode = CipherMode.CBC;

        public void AesMain(string plain_text)
        {
            PrintParam();
            Console.WriteLine("plain text : {0}", plain_text);
            string encrypt_text = Encrypt(plain_text);
            Console.WriteLine("encrypted text : {0}", encrypt_text);
            string decrypt_text = Decrypt(encrypt_text);
            Console.WriteLine("decrypted text : {0}", decrypt_text);
        }

        void PrintParam()
        {
            DrawLine();
            Console.WriteLine("AES");
            DrawLine();
            Console.WriteLine("CipherMode : {0}", this.mode);
            Console.WriteLine("BlockSize : {0}", this.block_size);
            Console.WriteLine("KeySize : {0}", this.key_size);
            Console.WriteLine("PaddingMode : {0}", this.padding);
            DrawLine();
        }

        string Encrypt(string plain_text)
        {
            string encrypted_text = "";

            // gabage collection for obj
            using (Aes myAes = Aes.Create())
            {
                myAes.Mode = this.mode;
                myAes.KeySize = this.key_size;
                myAes.Key = System.Text.Encoding.UTF8.GetBytes(this.AesKey);
                myAes.Padding = this.padding;
                myAes.Mode = this.mode;
                myAes.IV = System.Text.Encoding.UTF8.GetBytes(this.AesIV);

                ICryptoTransform encrypt = myAes.CreateEncryptor();
                MemoryStream memoryStream = new MemoryStream();
                CryptoStream cryptStream = new CryptoStream(memoryStream, encrypt, CryptoStreamMode.Write);

                byte[] text_bytes = System.Text.Encoding.UTF8.GetBytes(plain_text);

                cryptStream.Write(text_bytes, 0, text_bytes.Length);
                cryptStream.FlushFinalBlock();

                byte[] encrypted = memoryStream.ToArray();
                encrypted_text = System.Convert.ToBase64String(encrypted);
            }

            return encrypted_text;
        }

        string Decrypt(string encrypt_text)
        {
            string decrypted_text = "";

            using (Aes myAes = Aes.Create())
            {
                myAes.Mode = this.mode;
                myAes.KeySize = this.key_size;
                myAes.Key = System.Text.Encoding.UTF8.GetBytes(this.AesKey);
                myAes.Padding = this.padding;
                myAes.Mode = this.mode;
                myAes.IV = System.Text.Encoding.UTF8.GetBytes(this.AesIV);

                ICryptoTransform decryptor = myAes.CreateDecryptor();
                byte[] encrypted = System.Convert.FromBase64String(encrypt_text);
                byte[] planeText = new byte[encrypted.Length];

                MemoryStream memoryStream = new MemoryStream(encrypted);
                CryptoStream cryptStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

                cryptStream.Read(planeText, 0, planeText.Length);

                decrypted_text = System.Text.Encoding.UTF8.GetString(planeText);
            }

            return decrypted_text;
        }


        static void AesTest()
        {
            string original = "Here is some data to encrypt!";

            // Create a new instance of the Aes
            // class.  This generates a new key and initialization
            // vector (IV).
            using (Aes myAes = Aes.Create())
            {
                // Encrypt the string to an array of bytes.
                byte[] encrypted = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);

                // Decrypt the bytes to a string.
                string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

                //Display the original data and the decrypted data.
                Console.WriteLine("Original:   {0}", original);
                Console.WriteLine("Encrypted : {0}", System.Convert.ToBase64String(encrypted));
                Console.WriteLine("Decrypted : {0}", roundtrip);
            }
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}
