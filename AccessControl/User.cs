using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Security.Cryptography;

namespace AccessControl
{
    public class User
    {
        public string UserName { get; set; }
        public string Password_PlainText { get; set; }
        public string Password_Hash { get; set; }
        public string Password_SaltedHash { get; set; }
        public string Password_SaltedHashSlow { get; set; }
        public string Salt { get; set; }


        public User (string _UserName, string _Password)
        {
            UserName = _UserName;
            Password_PlainText = _Password;
        }

        public User ()
        {

        }

        public void AddUser()
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(Password_PlainText));
                this.Password_Hash = BytesToStringHex(hashBytes);
            }

            byte[] saltBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            this.Salt = BytesToStringHex(saltBytes);

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] saltedPassword = Encoding.UTF8.GetBytes(Password_PlainText + Salt);
                byte[] hashBytes = sha256.ComputeHash(saltedPassword);
                this.Password_SaltedHash = BytesToStringHex(hashBytes);
            }

            using (var pbkdf2 = new Rfc2898DeriveBytes(Password_PlainText, saltBytes, 10000, HashAlgorithmName.SHA256))
            {
                byte[] hashBytes = pbkdf2.GetBytes(32); // 32 bytes = 256 bits
                this.Password_SaltedHashSlow = BytesToStringHex(hashBytes);
            }

            ((App)Application.Current).Database.Add(this);            
        }

        public bool Validate (string _UserName, string _Password)
        {
            User MyUser = ((App)Application.Current).Database.Find(User => User.UserName == _UserName);
            
            if (MyUser == null)
                return false;

            // Validación con texto plano (solo para demostración)
            // if (MyUser.Password_PlainText.Equals(_Password))
            //     return true;

            // Validación con hash simple SHA256
            // using (SHA256 sha256 = SHA256.Create())
            // {
            //     byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(_Password));
            //     string hashedPassword = BytesToStringHex(hashBytes);
            //     if (MyUser.Password_Hash.Equals(hashedPassword))
            //         return true;
            // }

            // Validación con hash + salt SHA256
            // using (SHA256 sha256 = SHA256.Create())
            // {
            //     byte[] saltedPassword = Encoding.UTF8.GetBytes(_Password + MyUser.Salt);
            //     byte[] hashBytes = sha256.ComputeHash(saltedPassword);
            //     string hashedPassword = BytesToStringHex(hashBytes);
            //     if (MyUser.Password_SaltedHash.Equals(hashedPassword))
            //         return true;
            // }

            // Validación con hash lento + salt (PBKDF2)
            byte[] saltBytes = new byte[32];
            for (int i = 0; i < MyUser.Salt.Length; i += 2)
            {
                saltBytes[i / 2] = Convert.ToByte(MyUser.Salt.Substring(i, 2), 16);
            }

            using (var pbkdf2 = new Rfc2898DeriveBytes(_Password, saltBytes, 10000, HashAlgorithmName.SHA256))
            {
                byte[] hashBytes = pbkdf2.GetBytes(32);
                string hashedPassword = BytesToStringHex(hashBytes);
                if (MyUser.Password_SaltedHashSlow.Equals(hashedPassword))
                    return true;
            }

            return false;
        }

        string BytesToStringHex (byte[] result)
        {
            StringBuilder stringBuilder = new StringBuilder();

            foreach (byte b in result)
                stringBuilder.AppendFormat("{0:x2}", b);

            return stringBuilder.ToString();
        }
    }

}
