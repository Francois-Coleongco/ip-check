using ip_check.data_fetch;
using System.Data;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;
using DotNetEnv;

namespace ip_check
{
    /// <summary>  
    /// Interaction logic for MainWindow.xaml  
    /// </summary>  
    public partial class MainWindow : Window
    {

        private readonly DispatcherTimer _refreshTimer = new DispatcherTimer();
        private readonly FetchConns _fetcher = new FetchConns();

        public MainWindow()
        {
            Env.Load();
            InitializeComponent();
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            await RefreshDataGridAsync();

            _refreshTimer.Interval = TimeSpan.FromSeconds(2);
            _refreshTimer.Tick += async (s, args) => await RefreshDataGridAsync();
            _refreshTimer.Start();
        }

        private async Task RefreshDataGridAsync()
        {
            try
            {
                DataTable table = await _fetcher.PopulateDataTableTCP();
                connectionsData.ItemsSource = table.DefaultView;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}