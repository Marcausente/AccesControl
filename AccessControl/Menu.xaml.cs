using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace AccessControl
{
    /// <summary>
    /// Lógica de interacción para Menu.xaml
    /// </summary>
    public partial class Menu : Window
    {
        public Menu()
        {
            InitializeComponent();
        }

        private void Register_Click(object sender, RoutedEventArgs e)
        {
            Register RegisterWindow = new Register();
            RegisterWindow.Show();
        }

        private void Login_Click(object sender, RoutedEventArgs e)
        {
            Login LoginWindow = new Login();
            LoginWindow.Show();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Plain_Text.Text = ((App)Application.Current).Database[0].Password_PlainText;
            Hash.Text = ((App)Application.Current).Database[0].Password_Hash;
            Salt.Text = ((App)Application.Current).Database[0].Salt;
            Hash_salt.Text = ((App)Application.Current).Database[0].Password_SaltedHash;
            Iterat.Text = ((App)Application.Current).Database[0].Password_SaltedHashSlow;
        }
    }
}
