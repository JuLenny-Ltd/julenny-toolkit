#include "pch.h"
#include "App.xaml.h"
#include "MainWindow.xaml.h"

#include <winrt/Windows.UI.h>
#include <winrt/Microsoft.UI.Xaml.Media.Imaging.h>

#include <algorithm>

using namespace winrt;
using namespace winrt::Microsoft::UI::Xaml;

namespace winrt::JuLennyFHE::implementation
{
    App::App()
    {
        InitializeComponent();

        UnhandledException([this](IInspectable const&, UnhandledExceptionEventArgs const& e)
        {
            if (IsDebuggerPresent())
            {
                auto errorMessage = e.Message();
                __debugbreak();
            }
        });
    }

    void App::OnLaunched(LaunchActivatedEventArgs const&)
    {
        ShowSplashThenMain();
    }

    // The <uap:SplashScreen> entry in Package.appxmanifest never runs: the app ships
    // unpackaged (WindowsPackageType=None), the manifest is excluded from the build by a
    // condition in the vcxproj, and an OS splash screen is a packaged-app feature. So the
    // splash is a real window we show and close ourselves.
    void App::ShowSplashThenMain()
    {
        using namespace winrt::Microsoft::UI::Xaml::Controls;
        using namespace winrt::Microsoft::UI::Xaml::Media;
        using namespace winrt::Microsoft::UI::Windowing;

        m_splash = Window();

        Grid root;
        root.Background(SolidColorBrush(Windows::UI::Colors::White()));

        Imaging::BitmapImage bitmap{};
        bitmap.UriSource(Windows::Foundation::Uri(L"ms-appx:///Assets/Logo.png"));

        Image logo;
        logo.Source(bitmap);
        logo.Stretch(Stretch::Uniform);
        logo.Margin(Thickness{ 56, 40, 56, 40 });
        logo.HorizontalAlignment(HorizontalAlignment::Center);
        logo.VerticalAlignment(VerticalAlignment::Center);
        root.Children().Append(logo);

        m_splash.Content(root);

        auto appWindow = m_splash.AppWindow();
        if (auto presenter = appWindow.Presenter().try_as<OverlappedPresenter>())
        {
            presenter.SetBorderAndTitleBar(false, false);
            presenter.IsAlwaysOnTop(true);
        }

        // Size against the work area rather than in fixed pixels: AppWindow sizes are
        // physical, so a hard-coded width comes out tiny on a high-DPI display.
        auto const work = DisplayArea::GetFromWindowId(appWindow.Id(), DisplayAreaFallback::Primary).WorkArea();
        int32_t const width = std::clamp(static_cast<int32_t>(work.Width * 0.34), 420, 900);
        int32_t const height = static_cast<int32_t>(width * 0.42);
        appWindow.Resize({ width, height });
        appWindow.Move({ work.X + (work.Width - width) / 2, work.Y + (work.Height - height) / 2 });

        m_splash.Activate();

        m_splashTimer = DispatcherTimer();
        m_splashTimer.Interval(std::chrono::milliseconds(2200));
        m_splashTimer.Tick([this](IInspectable const&, IInspectable const&)
        {
            m_splashTimer.Stop();

            // Bring the main window up BEFORE closing the splash. Closing the only open
            // window first would tear the app down.
            m_window = make<JuLennyFHE::implementation::MainWindow>();
            m_window.Activate();

            if (m_splash)
            {
                m_splash.Close();
                m_splash = nullptr;
            }
        });
        m_splashTimer.Start();
    }
}
