using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace SecurityAlgorithmTest
{
    class MyKeySharing
    {
        Node alice = new Node();
        Node bob = new Node();
        
        public void KeySharingMain(string sharing_text="Secret Common Key.")
        {
            alice.PrintParam(nameof(alice));
            bob.PrintParam(nameof(bob));
            byte[] encrypt_text = alice.EncryptMessage(sharing_text, bob.GetPubKey());
            byte[] decrypt_text = bob.DecryptMessage(encrypt_text, alice.GetPubKey(), alice.GetIV());

            Console.WriteLine("sharing_text : {0}", sharing_text);
            Console.WriteLine("encrypt_text : {0}", Encoding.UTF8.GetString(encrypt_text));
            Console.WriteLine("decrypt_text : {0}", Encoding.UTF8.GetString(decrypt_text));
        }
    }

    class Node : MySecurityBase
    {
        ECDiffieHellmanKeyDerivationFunction kdf;
        CngAlgorithm chg_algorithm;
        int key_size;
        public ECDiffieHellmanCng node = new ECDiffieHellmanCng();
        byte[] iv;

        public Node()
        {
            kdf = ECDiffieHellmanKeyDerivationFunction.Hash;
            chg_algorithm = CngAlgorithm.Sha256;
            key_size = node.KeySize;
            //key_size = 256;
            RenewParam();
        }

        public void RenewParam()
        {
            this.node.KeyDerivationFunction = this.kdf;
            this.node.HashAlgorithm = this.chg_algorithm;
            this.node.KeySize = key_size;
        }

        public void PrintParam(string name)
        {
            DrawLine();
            Console.WriteLine("KeySharing ({0})", name);
            DrawLine();
            Console.WriteLine("KDF = {0}", this.node.KeyDerivationFunction);
            Console.WriteLine("Change Algorithm = {0}", this.node.HashAlgorithm);
            //Console.WriteLine("PublicKey[{1}] = {0}", PrintHex(this.node.PublicKey.ToByteArray(), 3), this.node.PublicKey.ToByteArray().Length);
            //Console.WriteLine("PublicKey[{1}] = {0}", System.Convert.ToBase64String(this.node.PublicKey.ToByteArray()), this.node.PublicKey.ToByteArray().Length);
            Console.WriteLine("PublicKeySize = {0}", this.node.PublicKey.ToByteArray().Length);
            DrawLine();
        }

        public byte[] GetPubKey()
        {
            return this.node.PublicKey.ToByteArray();
        }

        public byte[] GetIV()
        {
            return this.iv;
        }

        public byte[] GenerateDeriveKey(byte[] pub_key)
        {
            CngKey ClientKey = CngKey.Import(pub_key, CngKeyBlobFormat.EccPublicBlob);
            byte[] DeriveKey = node.DeriveKeyMaterial(ClientKey);
            return DeriveKey;
        }

        public byte[] EncryptMessage(string sharing_text, byte[] pub_key)
        {
            byte[] encrypt_text;
            
            using (Aes aes = new AesCryptoServiceProvider())
            {
                byte[] derive_key = GenerateDeriveKey(pub_key);
                aes.Key = derive_key;
                aes.Mode = CipherMode.CBC;
                iv = aes.IV;

                // Encrypt the message
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.UTF8.GetBytes(sharing_text);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encrypt_text = ciphertext.ToArray();
                }
            }

            return encrypt_text;
        }

        public byte[] DecryptMessage(byte[] encrypt_text, byte[] pub_key, byte[] iv)
        {
            byte[] decrypt_text;

            using (Aes aes = new AesCryptoServiceProvider())
            {
                byte[] derive_key = GenerateDeriveKey(pub_key);
                aes.Key = derive_key;
                aes.Mode = CipherMode.CBC;
                aes.IV = iv;

                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encrypt_text, 0, encrypt_text.Length);
                        cs.Close();
                        decrypt_text = plaintext.ToArray();
                    }
                }
            }

            return decrypt_text;
        }
    }

    class MyDH : MySecurityBase
    {
        ECDiffieHellmanKeyDerivationFunction kdf;
        CngAlgorithm chg_algorithm;
        byte[] iv = null;
        private byte[] receiverKey;

        public MyDH()
        {
            kdf = ECDiffieHellmanKeyDerivationFunction.Hash;
            chg_algorithm = CngAlgorithm.Sha256;
        }

        public void PrintParam(ECDiffieHellmanCng p, string name)
        {
            DrawLine();
            Console.WriteLine("KeySharing {0}", name);
            DrawLine();
            Console.WriteLine("KDF = {0}", p.KeyDerivationFunction);
            Console.WriteLine("Change Algorithm = {0}", p.HashAlgorithm);
            Console.WriteLine("PublicKey[{1}] = {0}", PrintHex(p.PublicKey.ToByteArray(), 3), p.PublicKey.ToByteArray().Length);
            DrawLine();
        }

        public void myDH_Main()
        {
            ECDiffieHellmanCng alice = new ECDiffieHellmanCng();
            ECDiffieHellmanCng bob = new ECDiffieHellmanCng();

            alice.KeyDerivationFunction = this.kdf;
            alice.HashAlgorithm = this.chg_algorithm;
            bob.KeyDerivationFunction = this.kdf;
            bob.HashAlgorithm = this.chg_algorithm;

            PrintParam(alice, nameof(alice));
            PrintParam(bob, nameof(bob));

            byte[] a = bob.PublicKey.ToByteArray();
            CngKey bobKey = CngKey.Import(bob.PublicKey.ToByteArray(), CngKeyBlobFormat.EccPublicBlob);
            byte[] aliceKey = alice.DeriveKeyMaterial(bobKey);
            byte[] encryptedMessage = null;
            string plain_text = "Secret message";
            Send(aliceKey, plain_text, out encryptedMessage, out iv);

            Console.WriteLine("Plain text : {0}", plain_text);
            Console.WriteLine("Send message (In Network) : {0}", Encoding.UTF8.GetString(encryptedMessage));

            receiverKey = bob.DeriveKeyMaterial(CngKey.Import(alice.PublicKey.ToByteArray(), CngKeyBlobFormat.EccPublicBlob));
            Receive(encryptedMessage, iv);
        }

        private static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage, out byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;

                // Encrypt the message
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encryptedMessage = ciphertext.ToArray();
                }
            }
        }

        public void Receive(byte[] encryptedMessage, byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = this.receiverKey;
                aes.IV = iv;
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                        cs.Close();
                        string message = Encoding.UTF8.GetString(plaintext.ToArray());
                        Console.WriteLine("Received Message : {0}", message);
                    }
                }
            }
        }
    }

}
