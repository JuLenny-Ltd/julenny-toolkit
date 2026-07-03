#include "pch.h"
#include "App.xaml.h"
#include "MainWindow.xaml.h"

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
        m_window = make<JuLennyFHE::implementation::MainWindow>();
        m_window.Activate();
    }
}
