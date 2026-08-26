#pragma once

#include "App.xaml.g.h"

namespace winrt::JuLennyFHE::implementation
{
    struct App : AppT<App>
    {
        App();

        void OnLaunched(Microsoft::UI::Xaml::LaunchActivatedEventArgs const&);

    private:
        // Show the brand splash, then hand over to the main window. Done by hand rather
        // than through the manifest; see App.xaml.cpp for why.
        void ShowSplashThenMain();

        winrt::Microsoft::UI::Xaml::Window m_window{ nullptr };
        winrt::Microsoft::UI::Xaml::Window m_splash{ nullptr };
        winrt::Microsoft::UI::Xaml::DispatcherTimer m_splashTimer{ nullptr };
    };
}
