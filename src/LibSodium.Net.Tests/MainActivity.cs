#if ANDROID
#pragma warning disable TUnit0031 // Async void methods are not allowed
namespace LibSodium.Net.Tests.Android
{
	[global::Android.App.Activity(
		Label = "TestRunner",
		MainLauncher = true,
		Theme = "@android:style/Theme.NoDisplay"
	)]
	public class MainActivity : global::Android.App.Activity
	{
		protected override void OnCreate(Bundle? savedInstanceState)
		{
			base.OnCreate(savedInstanceState);

			try
			{
				var context = this.ApplicationContext ?? throw new InvalidOperationException("ApplicationContext is null");
#pragma warning disable CA1416 // Validate platform compatibility
				var dataDir = context.DataDir ?? throw new InvalidOperationException("DataDir is null");
#pragma warning restore CA1416 // Validate platform compatibility
				var logFilePath = Path.Combine(dataDir.AbsolutePath, "log.txt");
				TextFileLogger.Initialize(logFilePath);
				var testResultsPath = Path.Combine(dataDir.AbsolutePath, "TestResults");
				Console.WriteLine($"TUNIT: Test results path: {testResultsPath}");
				var task = global::TestingPlatformEntryPoint.Main(["--hide-test-output", "--disable-logo",  "--diagnostic", "--report-trx", "--results-directory", testResultsPath]);
				Thread.Sleep(2000);
				TextFileLogger.Close();
			}
			catch (Exception ex)
			{
				Console.WriteLine($"TUNIT: EXCEPTION: {ex}");
			}

			Finish();
		}
	}
}
#pragma warning restore TUnit0031
#endif
