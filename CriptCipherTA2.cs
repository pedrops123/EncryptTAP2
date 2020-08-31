using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptDecryptProjetoTAP
{
    public class CriptCipherTA2
    {
        internal static string EncryptionKey = "ASYS2JC7ALC9013";
        static void Main(string[] args)
        {
            top:;
            Console.WriteLine("Escolha o que deseja fazer ");
            Console.WriteLine("1 - Descriptografar  ");
            Console.WriteLine("2 - Criptografar  ");

            var retorno = Console.ReadLine();
            switch(retorno){

                case "1":
                Console.WriteLine("Digite o texto a ser Descriptografado ");
                var textoDescript = Console.ReadLine();
                string textoDescriptografa = "";
                try
                {
                    textoDescriptografa = Decrypt(textoDescript);
                }
                catch(Exception e)
                {
                    Console.WriteLine(String.Format("Ocorreu um erro ao descriptograr o texto segue detalhes abaixo \n \n {0}", e));
                    goto top;
                }
                
                Console.WriteLine(String.Format("Seu texto Descriptografado é:  \n \n {0}",textoDescriptografa));
                goto top;
                break;


                case "2":
                 Console.WriteLine("Digite o texto a ser Criptografado ");
                var textoEncrypt = Console.ReadLine();

                var textoCriptografa = "";
                try
                {
                    textoCriptografa = Encrypt(textoEncrypt);
                }
                catch(Exception e)
                {
                    Console.WriteLine(String.Format("Ocorreu um erro ao Criptografar o texto segue detalhes abaixo \n \n {0}", e));
                    goto top;
                }
                Console.WriteLine(String.Format("Seu texto Criptografado é:  \n \n {0}",textoCriptografa));
                goto top;
                break;

                default:
                Console.WriteLine("Opção invalida !");
                goto top;
                break;


            }
            
        }

        public static string Encrypt(string clearText)
        {
            //if (!Valid.isBase64String(clearText))
            if (!String.IsNullOrEmpty(clearText))
            {
                byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(clearBytes, 0, clearBytes.Length);
                            cs.Close();
                        }
                        clearText = Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
            return clearText;
        }


        public static string Decrypt(string cipherText)
        {
            //if (Valid.isBase64String(cipherText))
            if (!String.IsNullOrEmpty(cipherText))
            {
                byte[] cipherBytes = Convert.FromBase64String(cipherText);
                using (Aes encryptor = Aes.Create())
                {
                    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                    encryptor.Key = pdb.GetBytes(32);
                    encryptor.IV = pdb.GetBytes(16);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(cipherBytes, 0, cipherBytes.Length);
                            cs.Close();
                        }
                        cipherText = Encoding.Unicode.GetString(ms.ToArray());
                    }
                }
            }
            return cipherText;
        }



    }    

}
