using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace SecurityAlgorithmTest
{
    class MyRsa : MySecurityBase
    {
        NodeRSA alice = new NodeRSA();
        NodeRSA bob = new NodeRSA();

        public void MyRsaMain(string plain_text)
        {
            byte[] hash;
            byte[] sign;
            PrintParam();

            alice.GenerateSign(plain_text, out hash, out sign);
            byte[] alice_pub_key = alice.GetPubKey();

            Console.WriteLine("plain text :\t {0}", plain_text);
            Console.WriteLine("hash :\t {0}", byte2str(hash));
            Console.WriteLine("sign :\t {0}", byte2str(sign));
            Console.WriteLine("sender pub key :\t {0}", byte2str(alice_pub_key));

            bool result = bob.VerifySign(plain_text, hash, sign, alice_pub_key);

            if( result == false)
            {
                Console.WriteLine("signature not valid");
            }
            else
            {
                Console.WriteLine("signature valid");
            }
            DrawLine();
        }

        public void PrintParam()
        {
            DrawLine();
            Console.WriteLine("RSA");
            DrawLine();
        }

        static void RsaTestMain()
        {
            try
            {
                //Create a new instance of RSA.
                using (RSA rsa = RSA.Create())
                {
                    //The hash to sign.
                    byte[] hash;
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        byte[] data = new byte[] { 59, 4, 248, 102, 77, 97, 142, 201, 210, 12, 224, 93, 25, 41, 100, 197, 213, 134, 130, 135 };
                        hash = sha256.ComputeHash(data);
                    }

                    //Create an RSASignatureFormatter object and pass it the 
                    //RSA instance to transfer the key information.
                    RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(rsa);

                    //Set the hash algorithm to SHA256.
                    RSAFormatter.SetHashAlgorithm("SHA256");

                    //Create a signature for HashValue and return it.
                    byte[] signedHash = RSAFormatter.CreateSignature(hash);
                    //Create an RSAPKCS1SignatureDeformatter object and pass it the  
                    //RSA instance to transfer the key information.
                    RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                    RSADeformatter.SetHashAlgorithm("SHA256");
                    //Verify the hash and display the results to the console. 
                    if (RSADeformatter.VerifySignature(hash, signedHash))
                    {
                        Console.WriteLine("The signature was verified.");
                    }
                    else
                    {
                        Console.WriteLine("The signature was not verified.");
                    }
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public void VerifySign(byte[] hash, byte[] signedHash)
        {
            using (RSA rsa = RSA.Create())
            {
                //Create an RSAPKCS1SignatureDeformatter object and pass it the  
                //RSA instance to transfer the key information.
                RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                RSADeformatter.SetHashAlgorithm("SHA256");
                //Verify the hash and display the results to the console. 
                if (RSADeformatter.VerifySignature(hash, signedHash))
                {
                    Console.WriteLine("The signature was verified.");
                }
                else
                {
                    Console.WriteLine("The signature was not verified.");
                }
            }
        }

        public void GenerateSign(byte[] input_data, out byte[] hash, out byte[] signedHash)
        {
            using (RSA rsa = RSA.Create())
            {
                //The hash to sign.
                using (SHA256 sha256 = SHA256.Create())
                {
                    hash = sha256.ComputeHash(input_data);
                }

                //Create an RSASignatureFormatter object and pass it the 
                //RSA instance to transfer the key information.
                RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(rsa);

                //Set the hash algorithm to SHA256.
                RSAFormatter.SetHashAlgorithm("SHA256");

                //Create a signature for HashValue and return it.
                signedHash = RSAFormatter.CreateSignature(hash);
            }
        }
    }

    class NodeRSA : MySecurityBase
    {
        byte[] document;
        CngKey chg_key;
        byte[] pub_key;
        HashAlgorithmName hash_algorithm_name;
        RSASignaturePadding padding;

        public NodeRSA()
        {
            this.chg_key = CngKey.Create(CngAlgorithm.Rsa);
            this.pub_key = this.chg_key.Export(CngKeyBlobFormat.GenericPublicBlob);
            this.hash_algorithm_name = HashAlgorithmName.SHA256;
            this.padding = RSASignaturePadding.Pss;
        }

        public void GenerateSign(string plain_text, out byte[] hash, out byte[] signed_hash)
        {
            this.document = str2byte(plain_text);
            using (SHA256 sha256 = SHA256.Create())
            {
                hash = sha256.ComputeHash(this.document);
            }
            signed_hash = AddSignatureToHash(hash, this.chg_key);
        }

        private byte[] AddSignatureToHash(byte[] hash, CngKey key)
        {
            using (var signingAlg = new RSACng(key))
            {
                return signingAlg.SignHash(hash, this.hash_algorithm_name, this.padding);
            }
        }

        public byte[] GetPubKey()
        {
            return this.pub_key;
        }

        public bool VerifySign(string plain_text, byte[] hash, byte[] signed_hash, byte[] pub_key_byte)
        {
            CngKey pub_key = CngKey.Import(pub_key_byte, CngKeyBlobFormat.GenericPublicBlob);
            using (var signingAlg = new RSACng(pub_key))
            {
                return signingAlg.VerifyHash(hash, signed_hash, this.hash_algorithm_name, this.padding);
            }
        }
    }
}
