using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace SecurityAlgorithmTest
{
    class Program
    {
        const string plain_text = "HelloWorld.";
        static void Main(string[] args)
        {
            MyAES aes = new MyAES();
            aes.mode = CipherMode.CBC;
            aes.AesMain(plain_text);
            Console.WriteLine();

            MyKeySharing ks = new MyKeySharing();
            ks.KeySharingMain();

            MyRsa rsa = new MyRsa();
            rsa.MyRsaMain(plain_text);

            Console.ReadLine();
        }
    }

    class MySecurityBase
    {
        public void DrawLine()
        {
            Console.WriteLine("------------------------------------------------------------");
        }

        public string PrintHex(byte[] bytes, UInt64 separation_num)
        {
            string res = "";
            UInt64 i = 0;
            foreach (byte b in bytes)
            {
                string text = string.Format("{0,2:X2}", b);

                if( i == 0 )
                {
                    res += "0x";
                }
                res += text;

                if ( i >= separation_num)
                {
                    res += " ";
                    i = 0;
                }
                else
                {
                    i++;
                }

            }
            return res;
        }

        public byte[] str2byte(string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }

        public string byte2str(byte[] bytes)
        {
            return Encoding.UTF8.GetString(bytes);
        }
    }

}
