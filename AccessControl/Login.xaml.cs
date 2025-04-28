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
    /// Lógica de interacción para Login.xaml
    /// </summary>
    public partial class Login : Window
    {
        public Login()
        {
            InitializeComponent();
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            User MyUser = new User();
            if (MyUser.Validate(UserName.Text,Password.Password))
                MessageBox.Show ("You are log in!!");
            else
                MessageBox.Show ("Login failed :-(");

        }

        private void UserName_GotFocus(object sender, RoutedEventArgs e)
        {
            if (UserName.Text.Equals("UserName"))
                UserName.Text = "";
        }

    }
}
