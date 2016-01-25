using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ecbpenguinnet
{
    class Program
    {
        static void Main(string[] args)
        {
            if(!File.Exists("tux.bmp")) { 
                Console.WriteLine("Make sure tux.bmp exists in the current folder");
            }

            using (FileStream fs = new FileStream("tux.bmp", FileMode.Open, FileAccess.Read))
            {
                long TOTAL = fs.Length;

                int HEADER_LENGTH = 14;  // 14 byte bmp header
                byte [] header = new byte[HEADER_LENGTH];
                fs.Read(header, 0, HEADER_LENGTH);

                int INFO_HEADER_LENGTH = 40; // 40-byte bmp info header
                byte [] infoheader = new byte[INFO_HEADER_LENGTH];
                fs.Read(infoheader, 0, INFO_HEADER_LENGTH);

                int REST = (int)TOTAL - (HEADER_LENGTH + INFO_HEADER_LENGTH);
                byte [] content = new byte[REST];
                fs.Read(content, 0, REST);

                WriteToFile(header,
                            infoheader,
                            Encrypt(content, CipherMode.ECB),
                            "tux_ecb.bmp");

                WriteToFile(header,
                            infoheader,
                            Encrypt(content, CipherMode.CBC),
                            "tux_cbc.bmp");

                fs.Close(); 
            }           

        }

        public static byte [] Encrypt(byte[] input, CipherMode cipherMode)
        {
            using (RijndaelManaged myRijndael = new RijndaelManaged { Mode = cipherMode })
            {

                myRijndael.GenerateKey();
                myRijndael.GenerateIV();

                ICryptoTransform encryptor = myRijndael.CreateEncryptor(myRijndael.Key, myRijndael.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(input, 0, input.Length);
                        csEncrypt.FlushFinalBlock();
                        return msEncrypt.ToArray();
                    }
                }
            }
        }

        public static void WriteToFile(byte [] header, byte [] infoheader, byte [] content, String fileToWrite)
        {
            using (FileStream fs = File.Create(fileToWrite))
            {
                fs.Write(header, 0, header.Length);
                fs.Write(infoheader, 0, infoheader.Length);
                fs.Write(content, 0, content.Length);
                fs.Flush();
                fs.Close();
            }
        }
    }
}
