#pragma once

#include "MainWindow.g.h"

namespace winrt::JuLennyFHE::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();

        // Navigation lifecycle
        void OnNavLoaded(winrt::Windows::Foundation::IInspectable const& sender,
                         winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnNavSelectionChanged(winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender,
                                   winrt::Microsoft::UI::Xaml::Controls::NavigationViewSelectionChangedEventArgs const& args);

        // Generate keypair screen
        winrt::fire_and_forget OnKeygenBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnKeygenGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                               winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Signing key (Ed25519 keypair) screen
        winrt::fire_and_forget OnSigningBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnSigningGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                 winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Keysetup share (chain on peer's public key) screen
        winrt::fire_and_forget OnKeysetupPeerBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnKeysetupOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnKeysetupGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                  winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Encrypt screen
        void OnEncryptSchemaChanged(winrt::Windows::Foundation::IInspectable const& sender,
                                     winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);
        void OnEncryptModeChanged(winrt::Windows::Foundation::IInspectable const& sender,
                                   winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnEncryptFunctionDefBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnEncryptInputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnEncryptKeyBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnEncryptOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnEncryptGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                 winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Partial decrypt screen
        winrt::fire_and_forget OnPartialInputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnPartialKeyBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnPartialOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnPartialGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                 winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Combine screen
        winrt::fire_and_forget OnCombineBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnCombineGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                 winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Sum combine screen
        winrt::fire_and_forget OnSumCombineShareABrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnSumCombineShareBBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnSumCombineJointPkBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnSumCombineOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnSumCombineGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                    winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Sum contribute screen
        void OnSumContributeRoleChanged(winrt::Windows::Foundation::IInspectable const& sender,
                                         winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);
        winrt::fire_and_forget OnSumContributeSecretKeyBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnSumContributePeerShareBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnSumContributeJointPkBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnSumContributeOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnSumContributeGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                       winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Relin contribute screen
        void OnRelinContributeRoundChanged(winrt::Windows::Foundation::IInspectable const& sender,
                                            winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);
        void OnRelinContributeRoleChanged(winrt::Windows::Foundation::IInspectable const& sender,
                                           winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);
        winrt::fire_and_forget OnRelinContributeSecretKeyBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRelinContributePeerShareBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRelinContributeCombinedR1BrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRelinContributeJointPkBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRelinContributeOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnRelinContributeGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                         winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Relin combine screen
        void OnRelinCombineRoundChanged(winrt::Windows::Foundation::IInspectable const& sender,
                                         winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);
        winrt::fire_and_forget OnRelinCombineShareABrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRelinCombineShareBBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRelinCombineJointPkBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRelinCombineCombinedR1BrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRelinCombineOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnRelinCombineGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                      winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Wrap upload (sign envelope) screen
        winrt::fire_and_forget OnWrapEnvelopePayloadBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnWrapEnvelopeSecretKeyBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnWrapEnvelopeOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnWrapEnvelopeGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                      winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Wrap final keys (sign finalization envelope) screen
        winrt::fire_and_forget OnWrapFinalKeysToSignBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnWrapFinalKeysSecretKeyBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnWrapFinalKeysOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnWrapFinalKeysGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                       winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Settings screen
        void OnSettingsRefreshClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                       winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Top-bar scheme picker. Sets the context spec (bfv-default-v1 or
        // ckks-default-v1) that every operation panel reads when building
        // its ToolkitClient options.
        void OnSchemeChanged(winrt::Windows::Foundation::IInspectable const& sender,
                              winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);

        // Rotation contribute screen (joint rotation key, required for CKKS
        // pipelines and any function whose function-def requiredEvalKeys
        // includes "rotation"). Mirrors sum-contribute plus an --indices field.
        void OnRotContributeRoleChanged(winrt::Windows::Foundation::IInspectable const& sender,
                                         winrt::Microsoft::UI::Xaml::Controls::SelectionChangedEventArgs const& args);
        winrt::fire_and_forget OnRotContributeSecretKeyBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRotContributePeerShareBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRotContributeJointPkBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRotContributeOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnRotContributeGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                       winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

        // Rotation combine screen (deterministic combine of both parties'
        // rotation-key contributions; mirrors sum combine).
        winrt::fire_and_forget OnRotCombineShareABrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRotCombineShareBBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRotCombineJointPkBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        winrt::fire_and_forget OnRotCombineOutputBrowseClicked(
                winrt::Windows::Foundation::IInspectable const& sender,
                winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnRotCombineGoClicked(winrt::Windows::Foundation::IInspectable const& sender,
                                    winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);

    private:
        void ShowPanel(std::wstring_view tag);
        void RefreshHomeStatus();
        void RefreshSettingsStatus();

        // Currently-selected crypto context spec, set by OnSchemeChanged.
        // Read by every panel handler when building ToolkitClient options.
        // Defaults to bfv-default-v1 (matching the ComboBox's IsSelected).
        std::string m_context_spec = "bfv-default-v1";
    };
}

namespace winrt::JuLennyFHE::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
