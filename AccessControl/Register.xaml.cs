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
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace AccessControl
{
    /// <summary>
    /// Lógica de interacción para MainWindow.xaml
    /// </summary>
    public partial class Register : Window
    {
        public Register()
        {
            InitializeComponent();            
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {            
            User MyUser = new User(UserName.Text, Password.Password);
            MyUser.AddUser();
            MessageBox.Show("Usuari registrat!");
            this.Close();
        }

        private void UserName_GotFocus(object sender, RoutedEventArgs e)
        {
            if (UserName.Text.Equals("UserName"))
                UserName.Text = "";
        }

    }
}
