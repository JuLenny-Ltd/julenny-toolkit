#include "pch.h"
#include "MainWindow.xaml.h"
#if __has_include("MainWindow.g.cpp")
#include "MainWindow.g.cpp"
#endif

#include "Services/ToolkitClient.h"

#include <nlohmann/json.hpp>

#include <cwctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace winrt;
using namespace winrt::Microsoft::UI::Xaml;
using namespace winrt::Microsoft::UI::Xaml::Controls;
using namespace winrt::Windows::Storage;
using namespace winrt::Windows::Storage::Pickers;

namespace winrt::JuLennyFHE::implementation
{
    namespace
    {
        // Narrow a wide UI string to std::string for the FFI. These strings are all
        // ASCII (tags, roles, ids, csv); the explicit per-char cast avoids C4244.
        inline std::string narrow(std::wstring const& w)
        {
            std::string s; s.reserve(w.size());
            for (wchar_t c : w) s.push_back(static_cast<char>(c));
            return s;
        }

        // List of (tag, panel-name-suffix) for the show/hide handler.
        // Keep in sync with MainWindow.xaml.
        struct PanelEntry { std::wstring_view tag; std::wstring_view panel_name; };
        constexpr PanelEntry kPanels[] = {
            { L"home",            L"HomePanel" },
            { L"keygen",          L"KeygenPanel" },
            { L"signing",         L"SigningPanel" },
            { L"keysetup",        L"KeysetupPanel" },
            { L"encrypt",         L"EncryptPanel" },
            { L"partial",         L"PartialPanel" },
            { L"combine",         L"CombinePanel" },
            { L"sumcontribute",   L"SumContributePanel" },
            { L"sumcombine",      L"SumCombinePanel" },
            { L"rotcontribute",   L"RotContributePanel" },
            { L"rotcombine",      L"RotCombinePanel" },
            { L"relincontribute", L"RelinContributePanel" },
            { L"relincombine",    L"RelinCombinePanel" },
            { L"wrapenvelope",    L"WrapEnvelopePanel" },
            { L"wrapfinalkeys",   L"WrapFinalKeysPanel" },
            { L"settings",        L"SettingsPanel" },
        };

        // WinUI 3 packaged-app requirement: file/folder pickers must be
        // associated with the host window's HWND before showing. Without
        // this the picker either throws or shows on the wrong monitor.
        void AssociatePickerWithWindow(::IInspectable* picker, winrt::Microsoft::UI::Xaml::Window const& window)
        {
            HWND hwnd{};
            auto windowNative = window.as<::IWindowNative>();
            check_hresult(windowNative->get_WindowHandle(&hwnd));

            ::IInitializeWithWindow* initialize_with_window{ nullptr };
            check_hresult(picker->QueryInterface(IID_PPV_ARGS(&initialize_with_window)));
            initialize_with_window->Initialize(hwnd);
            initialize_with_window->Release();
        }

        // --- Required-field validation helpers (shared across panels) ---
        // Each "Go" handler used to print a generic "fill in the fields"
        // message that didn't tell the user which control they missed.
        // These helpers paint empty controls' borders red and build a
        // specific "Missing field(s): X, Y" message so the user can see
        // exactly what's wrong without scanning the whole panel.

        // One field that needs to be non-empty before the user can act.
        struct RequiredField
        {
            std::wstring                                            label;
            winrt::Microsoft::UI::Xaml::Controls::Control           control;
            bool                                                    is_empty;
        };

        winrt::Microsoft::UI::Xaml::Media::Brush LookupThemeBrush(winrt::hstring const& key)
        {
            auto resources = winrt::Microsoft::UI::Xaml::Application::Current().Resources();
            if (!resources.HasKey(winrt::box_value(key))) return nullptr;
            return resources.Lookup(winrt::box_value(key))
                .try_as<winrt::Microsoft::UI::Xaml::Media::Brush>();
        }

        // Returns the list of missing-field labels and paints offenders red,
        // while resetting non-empty fields' borders to the default. The
        // returned vector is empty when every field is populated.
        std::vector<std::wstring> ValidateFields(std::vector<RequiredField> const& fields)
        {
            auto err_brush = LookupThemeBrush(L"SystemFillColorCriticalBrush");
            auto def_brush = LookupThemeBrush(L"ControlStrokeColorDefaultBrush");

            std::vector<std::wstring> missing;
            for (auto const& f : fields)
            {
                if (f.is_empty)
                {
                    if (err_brush) f.control.BorderBrush(err_brush);
                    missing.push_back(f.label);
                }
                else
                {
                    if (def_brush) f.control.BorderBrush(def_brush);
                }
            }
            return missing;
        }

        // Standard "Missing field(s) (highlighted in red): X, Y." sentence.
        std::wstring FormatMissingMessage(std::vector<std::wstring> const& missing)
        {
            std::wstring msg = L"Missing field(s) (highlighted in red): ";
            for (std::size_t i = 0; i < missing.size(); ++i)
            {
                if (i > 0) msg += L", ";
                msg += missing[i];
            }
            msg += L".";
            return msg;
        }
    }

    MainWindow::MainWindow()
    {
        InitializeComponent();

        // Set a sensible initial window size and center it on the current
        // display. WinUI 3's default sizing is ~75% of the screen which is
        // huge on ultra-wide monitors. Explicitly sizing here gives a
        // consistent experience across display configurations.
        try
        {
            HWND hwnd{};
            auto windowNative = this->try_as<::IWindowNative>();
            if (windowNative)
            {
                check_hresult(windowNative->get_WindowHandle(&hwnd));
                auto windowId = winrt::Microsoft::UI::GetWindowIdFromWindow(hwnd);
                auto appWindow = winrt::Microsoft::UI::Windowing::AppWindow::GetFromWindowId(windowId);
                if (appWindow)
                {
                    // Title-bar icon. app.rc embeds the icon as resource 1, which gives the
                    // exe its Explorer, taskbar and shortcut icon, but WinUI 3 draws its own
                    // title bar and shows a generic placeholder there unless the AppWindow is
                    // told explicitly. Reuse the icon already compiled into the exe rather
                    // than shipping a loose .ico beside it.
                    if (auto hicon = static_cast<HICON>(::LoadImageW(
                            ::GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1),
                            IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED)))
                    {
                        appWindow.SetIcon(winrt::Microsoft::UI::GetIconIdFromIcon(hicon));
                    }

                    constexpr int width  = 1200;
                    constexpr int height = 850;
                    appWindow.Resize({ width, height });

                    // Center on the current display's work area.
                    auto displayArea = winrt::Microsoft::UI::Windowing::DisplayArea::GetFromWindowId(
                        windowId,
                        winrt::Microsoft::UI::Windowing::DisplayAreaFallback::Nearest);
                    if (displayArea)
                    {
                        auto workArea = displayArea.WorkArea();
                        int32_t x = workArea.X + (workArea.Width  - width)  / 2;
                        int32_t y = workArea.Y + (workArea.Height - height) / 2;
                        appWindow.Move({ x, y });
                    }
                }
            }
        }
        catch (...) { /* fall back to default sizing if any of this fails */ }
    }

    // --- Navigation ---

    void MainWindow::OnNavLoaded(IInspectable const&, RoutedEventArgs const&)
    {
        // Default to Home on launch.
        NavView().SelectedItem(NavView().MenuItems().GetAt(0));
        RefreshHomeStatus();

        // Set default selection on the encrypt screen's schema picker now,
        // not in XAML. Doing it in XAML (via IsSelected on a ComboBoxItem)
        // fires SelectionChanged during XAML parsing, before the other
        // dependent controls on the same panel are constructed - which
        // crashes the handler with a null deref.
        if (EncryptSchemaCombo().SelectedIndex() < 0)
        {
            EncryptSchemaCombo().SelectedIndex(0);
        }

        // Default Encrypt-screen mode to Mode A (function-def). Setting
        // it here (after the panel is fully constructed) avoids the same
        // null-deref class of bug.
        EncryptModeARadio().IsChecked(true);
    }

    void MainWindow::OnNavSelectionChanged(NavigationView const&,
                                           NavigationViewSelectionChangedEventArgs const& args)
    {
        if (args.IsSettingsSelected())
        {
            ShowPanel(L"settings");
            RefreshSettingsStatus();
            return;
        }

        auto selected = args.SelectedItem().try_as<NavigationViewItem>();
        if (!selected) return;
        auto tag_obj = selected.Tag();
        if (!tag_obj) return;
        auto tag = unbox_value<hstring>(tag_obj);
        ShowPanel(std::wstring_view{ tag });

        if (std::wstring_view{ tag } == L"home")
        {
            RefreshHomeStatus();
        }
    }

    void MainWindow::ShowPanel(std::wstring_view tag)
    {
        for (const auto& p : kPanels)
        {
            auto element = Content().as<FrameworkElement>().FindName(p.panel_name);
            if (auto fe = element.try_as<FrameworkElement>())
            {
                fe.Visibility(p.tag == tag ? Visibility::Visible : Visibility::Collapsed);
            }
        }
    }

    // --- Home + Settings shared status ---

    void MainWindow::RefreshHomeStatus()
    {
        ::JuLennyFHE::Services::ToolkitClient client;
        auto status = client.GetLocalStatus();
        HomeStatusText().Text(status);
    }

    void MainWindow::RefreshSettingsStatus()
    {
        ::JuLennyFHE::Services::ToolkitClient client;
        auto status = client.GetLocalStatus();
        SettingsStatusText().Text(status);
    }

    void MainWindow::OnSettingsRefreshClicked(IInspectable const&, RoutedEventArgs const&)
    {
        RefreshSettingsStatus();
    }

    // --- Keygen screen ---

    fire_and_forget MainWindow::OnKeygenBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FolderPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        // FolderPicker requires at least one filter entry even though it
        // picks folders, not files.
        picker.FileTypeFilter().Append(L"*");

        auto folder = co_await picker.PickSingleFolderAsync();
        if (folder)
        {
            KeygenOutputDir().Text(folder.Path());
        }
    }

    void MainWindow::OnKeygenGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto dir_text = std::wstring{ KeygenOutputDir().Text() };

        auto missing = ValidateFields({
            { L"Output folder", KeygenOutputDir(), dir_text.empty() },
        });
        if (!missing.empty())
        {
            KeygenResultBorder().Visibility(Visibility::Visible);
            KeygenResultText().Text(FormatMissingMessage(missing));
            return;
        }

        // Generic FHE keypair generation. The output works for single-party
        // use, company-identity registration, or as the first contribution
        // in a joint keysetup. The Keysetup-share screen (separate) handles
        // the second-party chain-on-peer flow.
        KeygenResultBorder().Visibility(Visibility::Visible);
        KeygenResultText().Text(L"Generating FHE keypair...");
        KeygenGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::GenerateKeypairOptions opts;
        opts.output_secret_path = std::filesystem::path{ dir_text } / "fhe_secret_key.bin";
        opts.output_public_path = std::filesystem::path{ dir_text } / "fhe_public_key.bin";
        opts.context_spec       = m_context_spec;

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.GenerateKeypair(opts);

        KeygenResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        KeygenGoButton().IsEnabled(true);
    }

    // --- Signing key screen ---

    fire_and_forget MainWindow::OnSigningBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FolderPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L"*");

        auto folder = co_await picker.PickSingleFolderAsync();
        if (folder)
        {
            SigningOutputDir().Text(folder.Path());
        }
    }

    void MainWindow::OnSigningGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto dir_text = std::wstring{ SigningOutputDir().Text() };

        auto missing = ValidateFields({
            { L"Output folder", SigningOutputDir(), dir_text.empty() },
        });
        if (!missing.empty())
        {
            SigningResultBorder().Visibility(Visibility::Visible);
            SigningResultText().Text(FormatMissingMessage(missing));
            return;
        }

        SigningResultBorder().Visibility(Visibility::Visible);
        SigningResultText().Text(L"Generating signing keypair...");
        SigningGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::SigningKeygenOptions opts;
        opts.output_secret_path = std::filesystem::path{ dir_text } / "signing_secret_key.bin";
        opts.output_public_path = std::filesystem::path{ dir_text } / "signing_public_key.bin";

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.SigningKeygen(opts);

        SigningResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        SigningGoButton().IsEnabled(true);
    }

    // --- Keysetup share (chain on peer's pk) screen ---

    fire_and_forget MainWindow::OnKeysetupPeerBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");

        auto file = co_await picker.PickSingleFileAsync();
        if (file)
        {
            KeysetupPeerFile().Text(file.Path());
        }
    }

    fire_and_forget MainWindow::OnKeysetupOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FolderPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L"*");

        auto folder = co_await picker.PickSingleFolderAsync();
        if (folder)
        {
            KeysetupOutputDir().Text(folder.Path());
        }
    }

    void MainWindow::OnKeysetupGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto peer = std::wstring{ KeysetupPeerFile().Text() };
        auto dir  = std::wstring{ KeysetupOutputDir().Text() };

        auto missing = ValidateFields({
            { L"Peer's public-key contribution", KeysetupPeerFile(), peer.empty() },
            { L"Output folder",                  KeysetupOutputDir(), dir.empty()  },
        });
        if (!missing.empty())
        {
            KeysetupResultBorder().Visibility(Visibility::Visible);
            KeysetupResultText().Text(FormatMissingMessage(missing));
            return;
        }

        KeysetupResultBorder().Visibility(Visibility::Visible);
        KeysetupResultText().Text(L"Deriving joint public key...");
        KeysetupGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::KeysetupChainOptions opts;
        opts.peer_share_path    = std::filesystem::path{ peer };
        opts.output_secret_path = std::filesystem::path{ dir } / "my_share_secret.bin";
        opts.output_public_path = std::filesystem::path{ dir } / "joint_public_key.bin";
        opts.context_spec       = m_context_spec;

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.KeysetupChain(opts);

        KeysetupResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        KeysetupGoButton().IsEnabled(true);
    }

    // --- Encrypt screen ---

    void MainWindow::OnEncryptModeChanged(IInspectable const&, RoutedEventArgs const&)
    {
        // Guard: WinUI fires Checked on the first RadioButton in a GroupName
        // during XAML parsing, BEFORE the dependent StackPanels are
        // constructed. Calling .Visibility() on those uninitialized panels
        // produces an SEH access violation (which catch(...) doesn't catch
        // under the default /EHsc model). Defensive null-checks first.
        auto a_radio  = EncryptModeARadio();
        auto a_ctrls  = EncryptModeAControls();
        auto b_ctrls  = EncryptModeBControls();
        if (!a_radio || !a_ctrls || !b_ctrls) return;

        auto checked = a_radio.IsChecked();
        if (!checked) return;
        bool mode_a = checked.GetBoolean();

        a_ctrls.Visibility(mode_a ? Visibility::Visible : Visibility::Collapsed);
        b_ctrls.Visibility(mode_a ? Visibility::Collapsed : Visibility::Visible);
    }

    fire_and_forget MainWindow::OnEncryptFunctionDefBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".json");
        picker.FileTypeFilter().Append(L"*");

        auto file = co_await picker.PickSingleFileAsync();
        if (!file) co_return;

        std::wstring path_str{ file.Path() };
        EncryptFunctionDefFile().Text(path_str);

        // Parse the function-def JSON to populate the input-name dropdown.
        EncryptInputNameCombo().Items().Clear();
        try
        {
            std::ifstream in(std::filesystem::path{ path_str });
            if (!in)
            {
                EncryptInputNameCombo().PlaceholderText(L"Cannot open the selected file");
                co_return;
            }
            nlohmann::json fn_def;
            in >> fn_def;
            if (!fn_def.contains("inputs") || !fn_def["inputs"].is_array() || fn_def["inputs"].empty())
            {
                EncryptInputNameCombo().PlaceholderText(L"This function definition has no inputs");
                co_return;
            }
            for (const auto& input : fn_def["inputs"])
            {
                std::string name = input.value("name", std::string{});
                std::string role = input.value("role", std::string{});
                if (name.empty()) continue;
                Controls::ComboBoxItem item;
                std::wstring label;
                for (char c : name) label.push_back(static_cast<wchar_t>(c));
                if (!role.empty())
                {
                    label.append(L"  (");
                    for (char c : role) label.push_back(static_cast<wchar_t>(c));
                    label.push_back(L')');
                }
                item.Content(box_value(hstring{ label }));
                std::wstring tag_w;
                for (char c : name) tag_w.push_back(static_cast<wchar_t>(c));
                item.Tag(box_value(hstring{ tag_w }));
                EncryptInputNameCombo().Items().Append(item);
            }
            EncryptInputNameCombo().PlaceholderText(L"Pick the input this dataset is for");
        }
        catch (const std::exception& e)
        {
            std::wstring err = L"Failed to parse function-def JSON: ";
            for (char c : std::string(e.what())) err.push_back(static_cast<wchar_t>(c));
            EncryptInputNameCombo().PlaceholderText(hstring{ err });
        }
    }

    void MainWindow::OnEncryptSchemaChanged(IInspectable const&,
                                            Controls::SelectionChangedEventArgs const&)
    {
        // Defensive: the handler can theoretically fire before dependent
        // controls are constructed. Bail out silently if any are missing.
        try
        {
            auto combo = EncryptSchemaCombo();
            auto selected = combo.SelectedItem().try_as<Controls::ComboBoxItem>();
            if (!selected) return;
            auto tag_obj = selected.Tag();
            if (!tag_obj) return;
            auto tag = unbox_value<hstring>(tag_obj);
            std::wstring_view tag_sv{ tag };

        if (tag_sv == L"indicator-hash")
        {
            EncryptSchemaDescription().Text(
                L"Each record (one line in your input file) becomes a 1 at the slot whose position is the hash of that record. "
                L"Used for set membership, intersection, and search functions like joint-record-overlap. "
                L"Input can be plain text (one record per line), CSV, TSV, or any line-separated format.");
            EncryptInputLabel().Text(L"Input file");
            EncryptInputFile().PlaceholderText(L"Click Browse to pick a file");
            EncryptIndicatorOptions().Visibility(Visibility::Visible);
        }
        else if (tag_sv == L"packed-int")
        {
            EncryptSchemaDescription().Text(
                L"Each line in your file is an integer placed into one slot in order. "
                L"Used for element-wise numeric functions (each slot is independent).");
            EncryptInputLabel().Text(L"Input file (one integer per line)");
            EncryptInputFile().PlaceholderText(L"Click Browse to pick a text file");
            EncryptIndicatorOptions().Visibility(Visibility::Collapsed);
        }
        }
        catch (...)
        {
            // Controls not fully constructed yet; selection-changed handler will
            // re-run once OnNavLoaded sets the index explicitly.
        }
    }

    fire_and_forget MainWindow::OnEncryptInputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        // Keep the window alive across the co_await.
        auto lifetime = get_strong();

        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L"*");

        auto file = co_await picker.PickSingleFileAsync();
        if (file)
        {
            EncryptInputFile().Text(file.Path());
        }
    }

    fire_and_forget MainWindow::OnEncryptKeyBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");

        auto file = co_await picker.PickSingleFileAsync();
        if (file)
        {
            EncryptKeyFile().Text(file.Path());
        }
    }

    fire_and_forget MainWindow::OnEncryptOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"ciphertext");

        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".bin");
        picker.FileTypeChoices().Insert(L"Encrypted ciphertext", extensions);

        auto file = co_await picker.PickSaveFileAsync();
        if (file)
        {
            EncryptOutputFile().Text(file.Path());
        }
    }

    void MainWindow::OnEncryptGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto input  = std::wstring{ EncryptInputFile().Text() };
        auto key    = std::wstring{ EncryptKeyFile().Text() };
        auto output = std::wstring{ EncryptOutputFile().Text() };

        auto missing = ValidateFields({
            { L"Input file",      EncryptInputFile(),  input.empty()  },
            { L"Joint public key", EncryptKeyFile(),    key.empty()    },
            { L"Output file",     EncryptOutputFile(), output.empty() },
        });
        if (!missing.empty())
        {
            EncryptResultBorder().Visibility(Visibility::Visible);
            EncryptResultText().Text(FormatMissingMessage(missing));
            return;
        }

        ::JuLennyFHE::Services::EncryptOptions opts;
        opts.input_path             = std::filesystem::path{ input };
        opts.joint_public_key_path  = std::filesystem::path{ key };
        opts.output_path            = std::filesystem::path{ output };
        // EncryptOptions.context_spec is an OPTIONAL override; ToolkitClient
        // reads from function-def when this is empty. We always set it from
        // the UI picker so the operator's selection wins over the function-
        // def default. If the user mismatches the picker against the
        // function-def's required scheme, the lib surfaces an error.
        opts.context_spec           = m_context_spec;

        // Populate either Mode-A fields (function-def + input-name) or
        // Mode-B fields (schema + per-schema flags) depending on which
        // radio button is selected.
        const bool mode_a = EncryptModeARadio().IsChecked().GetBoolean();
        if (mode_a)
        {
            auto fn_def_path = std::wstring{ EncryptFunctionDefFile().Text() };
            auto input_item = EncryptInputNameCombo().SelectedItem().try_as<Controls::ComboBoxItem>();

            auto mode_a_missing = ValidateFields({
                { L"Function-definition file", EncryptFunctionDefFile(), fn_def_path.empty() },
                { L"Input name",               EncryptInputNameCombo(),  !input_item        },
            });
            if (!mode_a_missing.empty())
            {
                EncryptResultBorder().Visibility(Visibility::Visible);
                EncryptResultText().Text(FormatMissingMessage(mode_a_missing));
                return;
            }

            opts.function_def_path = std::filesystem::path{ fn_def_path };
            auto tag = winrt::unbox_value_or<winrt::hstring>(input_item.Tag(), L"");
            std::wstring tag_w{ tag };
            opts.input_name = narrow(tag_w);
        }
        else
        {
            auto schema_item = EncryptSchemaCombo().SelectedItem().try_as<Controls::ComboBoxItem>();
            if (schema_item)
            {
                auto tag = winrt::unbox_value_or<winrt::hstring>(schema_item.Tag(), L"indicator-hash");
                std::wstring tag_w{ tag };
                opts.schema = narrow(tag_w);
            }
            auto sep_item = EncryptSeparator().SelectedItem().try_as<Controls::ComboBoxItem>();
            if (sep_item)
            {
                auto tag = winrt::unbox_value_or<winrt::hstring>(sep_item.Tag(), L"none");
                std::wstring tag_w{ tag };
                opts.separator = narrow(tag_w);
            }
            opts.skip_header = EncryptSkipHeader().IsChecked().GetBoolean();
            auto cols_w = std::wstring{ EncryptColumns().Text() };
            opts.columns = narrow(cols_w);
        }

        EncryptResultBorder().Visibility(Visibility::Visible);
        EncryptResultText().Text(L"Encrypting...");
        EncryptGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.Encrypt(opts);

        EncryptResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        EncryptGoButton().IsEnabled(true);
    }

    // --- Partial decrypt screen ---

    fire_and_forget MainWindow::OnPartialInputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");

        auto file = co_await picker.PickSingleFileAsync();
        if (file)
        {
            PartialInputFile().Text(file.Path());
        }
    }

    fire_and_forget MainWindow::OnPartialKeyBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");

        auto file = co_await picker.PickSingleFileAsync();
        if (file)
        {
            PartialKeyFile().Text(file.Path());
        }
    }

    fire_and_forget MainWindow::OnPartialOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"partial");

        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".bin");
        picker.FileTypeChoices().Insert(L"Partial decryption", extensions);

        auto file = co_await picker.PickSaveFileAsync();
        if (file)
        {
            PartialOutputFile().Text(file.Path());
        }
    }

    void MainWindow::OnPartialGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto input  = std::wstring{ PartialInputFile().Text() };
        auto key    = std::wstring{ PartialKeyFile().Text() };
        auto output = std::wstring{ PartialOutputFile().Text() };

        auto missing = ValidateFields({
            { L"Ciphertext file",   PartialInputFile(),  input.empty()  },
            { L"Secret key share",  PartialKeyFile(),    key.empty()    },
            { L"Output file",       PartialOutputFile(), output.empty() },
        });
        if (!missing.empty())
        {
            PartialResultBorder().Visibility(Visibility::Visible);
            PartialResultText().Text(FormatMissingMessage(missing));
            return;
        }

        // Read the lead checkbox: exactly one party in a multi-party
        // decryption is the "lead" (the recipient who'll combine all
        // partials to recover the plaintext); the other parties are "main".
        ::JuLennyFHE::Services::PartialDecryptOptions opts;
        opts.ciphertext_path = std::filesystem::path{ input };
        opts.secret_key_path = std::filesystem::path{ key };
        opts.output_path     = std::filesystem::path{ output };
        opts.is_lead         = PartialLeadCheckbox().IsChecked().GetBoolean();
        opts.context_spec    = m_context_spec;

        PartialResultBorder().Visibility(Visibility::Visible);
        PartialResultText().Text(L"Producing partial decryption...");
        PartialGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.PartialDecrypt(opts);

        PartialResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        PartialGoButton().IsEnabled(true);
    }

    // --- Combine screen ---

    fire_and_forget MainWindow::OnCombineBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();

        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);

        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");

        auto files = co_await picker.PickMultipleFilesAsync();
        if (files && files.Size() > 0)
        {
            // Display one file path per line in the multi-line textbox.
            std::wstring combined;
            for (uint32_t i = 0; i < files.Size(); ++i)
            {
                if (i > 0) combined.push_back(L'\n');
                combined.append(files.GetAt(i).Path());
            }
            CombinePartialsBox().Text(combined);
        }
    }

    void MainWindow::OnCombineGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        // Parse one path per line from the multi-line input box. Lines are
        // separated by \r, \n, or \r\n; trim whitespace and skip empties.
        std::wstring all = std::wstring{ CombinePartialsBox().Text() };
        std::vector<std::filesystem::path> partial_paths;
        std::wstring current;
        auto flush = [&]() {
            // Trim trailing whitespace.
            while (!current.empty() && std::iswspace(current.back())) current.pop_back();
            // Trim leading whitespace.
            std::size_t start = 0;
            while (start < current.size() && std::iswspace(current[start])) ++start;
            if (start < current.size())
            {
                partial_paths.emplace_back(current.substr(start));
            }
            current.clear();
        };
        for (wchar_t c : all)
        {
            if (c == L'\n' || c == L'\r') flush();
            else current.push_back(c);
        }
        flush();

        if (partial_paths.size() < 2)
        {
            auto missing = ValidateFields({
                { L"Partial decryption files (need at least 2)",
                  CombinePartialsBox(), partial_paths.size() < 2 },
            });
            CombineResultBorder().Visibility(Visibility::Visible);
            CombineResultText().Text(FormatMissingMessage(missing));
            return;
        }

        ::JuLennyFHE::Services::CombineOptions opts;
        opts.partial_paths = std::move(partial_paths);
        opts.context_spec  = m_context_spec;

        CombineResultBorder().Visibility(Visibility::Visible);
        CombineResultText().Text(L"Combining partial decryptions...");
        CombineGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.CombinePartials(opts);

        if (result.success)
        {
            // Show the summary plus a preview of the first nonzero slots
            // (or the first slot's value, which for joint-record-overlap
            // is the overlap count).
            std::wostringstream out;
            out << result.summary << L"\n\n";
            out << L"Answer (slot 0): " << (result.slots.empty() ? 0LL : result.slots[0]) << L"\n";
            if (result.non_zero_slots > 0 && result.non_zero_slots <= 32)
            {
                out << L"\nNonzero slot positions and values:\n";
                for (std::size_t i = 0; i < result.slots.size(); ++i)
                {
                    if (result.slots[i] != 0)
                    {
                        out << L"  [" << i << L"] = " << result.slots[i] << L"\n";
                    }
                }
            }
            else if (result.non_zero_slots > 32)
            {
                out << L"\n(too many nonzero slots to display; sum-of-slots and answer above)";
            }
            CombineResultText().Text(out.str());
        }
        else
        {
            CombineResultText().Text(L"Error: " + result.error);
        }
        CombineGoButton().IsEnabled(true);
    }

    // --- Sum combine screen ---

    fire_and_forget MainWindow::OnSumCombineShareABrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) SumCombineShareA().Text(file.Path());
    }

    fire_and_forget MainWindow::OnSumCombineShareBBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) SumCombineShareB().Text(file.Path());
    }

    fire_and_forget MainWindow::OnSumCombineJointPkBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) SumCombineJointPk().Text(file.Path());
    }

    fire_and_forget MainWindow::OnSumCombineOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"sum_key");
        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".bin");
        picker.FileTypeChoices().Insert(L"Binary", extensions);
        auto file = co_await picker.PickSaveFileAsync();
        if (file) SumCombineOutput().Text(file.Path());
    }

    void MainWindow::OnSumCombineGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto a   = std::wstring{ SumCombineShareA().Text() };
        auto b   = std::wstring{ SumCombineShareB().Text() };
        auto jpk = std::wstring{ SumCombineJointPk().Text() };
        auto out = std::wstring{ SumCombineOutput().Text() };

        auto missing = ValidateFields({
            { L"Share A",          SumCombineShareA(),   a.empty()   },
            { L"Share B",          SumCombineShareB(),   b.empty()   },
            { L"Joint public key", SumCombineJointPk(),  jpk.empty() },
            { L"Output file",      SumCombineOutput(),   out.empty() },
        });
        if (!missing.empty())
        {
            SumCombineResultBorder().Visibility(Visibility::Visible);
            SumCombineResultText().Text(FormatMissingMessage(missing));
            return;
        }

        SumCombineResultBorder().Visibility(Visibility::Visible);
        SumCombineResultText().Text(L"Combining sum-key contributions...");
        SumCombineGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::SumCombineOptions opts;
        opts.share_a_path  = std::filesystem::path{ a };
        opts.share_b_path  = std::filesystem::path{ b };
        opts.joint_pk_path = std::filesystem::path{ jpk };
        opts.output_path   = std::filesystem::path{ out };
        opts.context_spec  = m_context_spec;

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.SumCombine(opts);

        SumCombineResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        SumCombineGoButton().IsEnabled(true);
    }

    // --- Sum contribute screen ---

    void MainWindow::OnSumContributeRoleChanged(IInspectable const&,
                                                 Controls::SelectionChangedEventArgs const&)
    {
        try
        {
            auto fields = SumContributeMainFields();
            auto combo  = SumContributeRole();
            if (!fields || !combo) return;
            auto sel = combo.SelectedItem().try_as<Controls::ComboBoxItem>();
            if (!sel) { fields.Visibility(Visibility::Collapsed); return; }
            auto tag = winrt::unbox_value_or<winrt::hstring>(sel.Tag(), L"");
            fields.Visibility(std::wstring{ tag } == L"main" ? Visibility::Visible : Visibility::Collapsed);
        }
        catch (...) {}
    }

    fire_and_forget MainWindow::OnSumContributeSecretKeyBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) SumContributeSecretKey().Text(file.Path());
    }

    fire_and_forget MainWindow::OnSumContributePeerShareBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) SumContributePeerShare().Text(file.Path());
    }

    fire_and_forget MainWindow::OnSumContributeJointPkBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) SumContributeJointPk().Text(file.Path());
    }

    fire_and_forget MainWindow::OnSumContributeOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"sum_contribution");
        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".bin");
        picker.FileTypeChoices().Insert(L"Binary", extensions);
        auto file = co_await picker.PickSaveFileAsync();
        if (file) SumContributeOutput().Text(file.Path());
    }

    void MainWindow::OnSumContributeGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto role_item = SumContributeRole().SelectedItem().try_as<Controls::ComboBoxItem>();
        auto sk  = std::wstring{ SumContributeSecretKey().Text() };
        auto out = std::wstring{ SumContributeOutput().Text() };

        // Validate the always-required fields (role, secret key, output)
        // plus the role=main-only fields (peer share, joint pk) when that
        // role is selected. Doing it in one pass means the user sees every
        // missing field at once, not one at a time.
        std::wstring role_w;
        if (role_item)
        {
            auto role_tag = winrt::unbox_value_or<winrt::hstring>(role_item.Tag(), L"");
            role_w = std::wstring{ role_tag };
        }
        const bool is_main = (role_w == L"main");
        auto peer = std::wstring{ SumContributePeerShare().Text() };
        auto jpk  = std::wstring{ SumContributeJointPk().Text() };

        std::vector<RequiredField> required = {
            { L"Role",         SumContributeRole(),       !role_item   },
            { L"Secret key",   SumContributeSecretKey(),  sk.empty()   },
            { L"Output file",  SumContributeOutput(),     out.empty()  },
        };
        if (is_main)
        {
            required.push_back({ L"Peer's contribution", SumContributePeerShare(), peer.empty() });
            required.push_back({ L"Joint public key",    SumContributeJointPk(),   jpk.empty()  });
        }
        auto missing = ValidateFields(required);
        if (!missing.empty())
        {
            SumContributeResultBorder().Visibility(Visibility::Visible);
            SumContributeResultText().Text(FormatMissingMessage(missing));
            return;
        }

        ::JuLennyFHE::Services::SumContributeOptions opts;
        opts.role = narrow(role_w);
        opts.secret_key_path = std::filesystem::path{ sk };
        opts.output_path     = std::filesystem::path{ out };
        opts.context_spec    = m_context_spec;

        if (is_main)
        {
            opts.peer_share_path = std::filesystem::path{ peer };
            opts.joint_pk_path   = std::filesystem::path{ jpk };
        }

        SumContributeResultBorder().Visibility(Visibility::Visible);
        SumContributeResultText().Text(L"Computing sum-key contribution...");
        SumContributeGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.SumContribute(opts);

        SumContributeResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        SumContributeGoButton().IsEnabled(true);
    }

    // --- Relin contribute screen ---

    void MainWindow::OnRelinContributeRoundChanged(IInspectable const&,
                                                    Controls::SelectionChangedEventArgs const&)
    {
        try
        {
            auto r1 = RelinContributeRound1Fields();
            auto r2 = RelinContributeRound2Fields();
            auto main = RelinContributeMainFields();
            auto combo = RelinContributeRound();
            if (!r1 || !r2 || !main || !combo) return;
            auto sel = combo.SelectedItem().try_as<Controls::ComboBoxItem>();
            if (!sel) return;
            auto tag = winrt::unbox_value_or<winrt::hstring>(sel.Tag(), L"");
            bool is_round_1 = std::wstring{ tag } == L"1";
            r1.Visibility(is_round_1 ? Visibility::Visible : Visibility::Collapsed);
            r2.Visibility(is_round_1 ? Visibility::Collapsed : Visibility::Visible);
            // Hide the main-only fields whenever round changes; the role
            // dropdown's handler re-shows them if needed.
            if (!is_round_1) main.Visibility(Visibility::Collapsed);
        }
        catch (...) {}
    }

    void MainWindow::OnRelinContributeRoleChanged(IInspectable const&,
                                                   Controls::SelectionChangedEventArgs const&)
    {
        try
        {
            auto main = RelinContributeMainFields();
            auto combo = RelinContributeRole();
            if (!main || !combo) return;
            auto sel = combo.SelectedItem().try_as<Controls::ComboBoxItem>();
            if (!sel) { main.Visibility(Visibility::Collapsed); return; }
            auto tag = winrt::unbox_value_or<winrt::hstring>(sel.Tag(), L"");
            main.Visibility(std::wstring{ tag } == L"main" ? Visibility::Visible : Visibility::Collapsed);
        }
        catch (...) {}
    }

    fire_and_forget MainWindow::OnRelinContributeSecretKeyBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RelinContributeSecretKey().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRelinContributePeerShareBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RelinContributePeerShare().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRelinContributeCombinedR1BrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RelinContributeCombinedR1().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRelinContributeJointPkBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RelinContributeJointPk().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRelinContributeOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"relin_contribution");
        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".bin");
        picker.FileTypeChoices().Insert(L"Binary", extensions);
        auto file = co_await picker.PickSaveFileAsync();
        if (file) RelinContributeOutput().Text(file.Path());
    }

    void MainWindow::OnRelinContributeGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto round_item = RelinContributeRound().SelectedItem().try_as<Controls::ComboBoxItem>();
        std::wstring round_w;
        if (round_item)
        {
            auto round_tag = winrt::unbox_value_or<winrt::hstring>(round_item.Tag(), L"");
            round_w = std::wstring{ round_tag };
        }
        const int round = (round_w == L"2") ? 2 : 1;

        auto sk  = std::wstring{ RelinContributeSecretKey().Text() };
        auto out = std::wstring{ RelinContributeOutput().Text() };

        auto role_item = RelinContributeRole().SelectedItem().try_as<Controls::ComboBoxItem>();
        std::wstring role_w;
        if (role_item)
        {
            auto role_tag = winrt::unbox_value_or<winrt::hstring>(role_item.Tag(), L"");
            role_w = std::wstring{ role_tag };
        }
        auto peer = std::wstring{ RelinContributePeerShare().Text() };
        auto c1   = std::wstring{ RelinContributeCombinedR1().Text() };
        auto jpk  = std::wstring{ RelinContributeJointPk().Text() };

        // Always required: round, secret key, output.
        // Conditional on round: role (round 1), peer share (round 1 + role=main),
        // combined-r1 + joint-pk (round 2). Build the list in one pass so
        // every missing field is reported and highlighted together.
        std::vector<RequiredField> required = {
            { L"Round",       RelinContributeRound(),     !round_item },
            { L"Secret key",  RelinContributeSecretKey(), sk.empty()  },
            { L"Output file", RelinContributeOutput(),    out.empty() },
        };
        if (round == 1)
        {
            required.push_back({ L"Role", RelinContributeRole(), !role_item });
            if (role_w == L"main")
            {
                required.push_back({ L"Lead's round-1 contribution",
                                     RelinContributePeerShare(), peer.empty() });
            }
        }
        else
        {
            required.push_back({ L"Combined round-1 file",
                                 RelinContributeCombinedR1(), c1.empty() });
            required.push_back({ L"Joint public key",
                                 RelinContributeJointPk(), jpk.empty() });
        }

        auto missing = ValidateFields(required);
        if (!missing.empty())
        {
            RelinContributeResultBorder().Visibility(Visibility::Visible);
            RelinContributeResultText().Text(FormatMissingMessage(missing));
            return;
        }

        ::JuLennyFHE::Services::RelinContributeOptions opts;
        opts.round = round;
        opts.secret_key_path = std::filesystem::path{ sk };
        opts.output_path     = std::filesystem::path{ out };
        opts.context_spec    = m_context_spec;

        if (round == 1)
        {
            opts.role = narrow(role_w);
            if (role_w == L"main")
            {
                opts.peer_share_path = std::filesystem::path{ peer };
            }
        }
        else
        {
            opts.combined_r1_path = std::filesystem::path{ c1 };
            opts.joint_pk_path    = std::filesystem::path{ jpk };
        }

        RelinContributeResultBorder().Visibility(Visibility::Visible);
        RelinContributeResultText().Text(L"Computing relinearization-key contribution...");
        RelinContributeGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.RelinContribute(opts);

        RelinContributeResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        RelinContributeGoButton().IsEnabled(true);
    }

    // --- Relin combine screen ---

    void MainWindow::OnRelinCombineRoundChanged(IInspectable const&,
                                                 Controls::SelectionChangedEventArgs const&)
    {
        try
        {
            auto r1 = RelinCombineRound1Fields();
            auto r2 = RelinCombineRound2Fields();
            auto combo = RelinCombineRound();
            if (!r1 || !r2 || !combo) return;
            auto sel = combo.SelectedItem().try_as<Controls::ComboBoxItem>();
            if (!sel) return;
            auto tag = winrt::unbox_value_or<winrt::hstring>(sel.Tag(), L"");
            bool is_round_1 = std::wstring{ tag } == L"1";
            r1.Visibility(is_round_1 ? Visibility::Visible : Visibility::Collapsed);
            r2.Visibility(is_round_1 ? Visibility::Collapsed : Visibility::Visible);
        }
        catch (...) {}
    }

    fire_and_forget MainWindow::OnRelinCombineShareABrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RelinCombineShareA().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRelinCombineShareBBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RelinCombineShareB().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRelinCombineJointPkBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RelinCombineJointPk().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRelinCombineCombinedR1BrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RelinCombineCombinedR1().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRelinCombineOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"relin_combined");
        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".bin");
        picker.FileTypeChoices().Insert(L"Binary", extensions);
        auto file = co_await picker.PickSaveFileAsync();
        if (file) RelinCombineOutput().Text(file.Path());
    }

    void MainWindow::OnRelinCombineGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto round_item = RelinCombineRound().SelectedItem().try_as<Controls::ComboBoxItem>();
        std::wstring round_w;
        if (round_item)
        {
            auto round_tag = winrt::unbox_value_or<winrt::hstring>(round_item.Tag(), L"");
            round_w = std::wstring{ round_tag };
        }
        const int round = (round_w == L"2") ? 2 : 1;

        auto a   = std::wstring{ RelinCombineShareA().Text() };
        auto b   = std::wstring{ RelinCombineShareB().Text() };
        auto out = std::wstring{ RelinCombineOutput().Text() };
        auto jpk = std::wstring{ RelinCombineJointPk().Text() };
        auto c1  = std::wstring{ RelinCombineCombinedR1().Text() };

        // Round-conditional: round 1 needs the joint-pk; round 2 needs the
        // combined-r1 file. Build the required list in one pass so the user
        // sees every missing field at once.
        std::vector<RequiredField> required = {
            { L"Round",       RelinCombineRound(),  !round_item },
            { L"Share A",     RelinCombineShareA(), a.empty()   },
            { L"Share B",     RelinCombineShareB(), b.empty()   },
            { L"Output file", RelinCombineOutput(), out.empty() },
        };
        if (round == 1)
        {
            required.push_back({ L"Joint public key", RelinCombineJointPk(), jpk.empty() });
        }
        else
        {
            required.push_back({ L"Combined round-1 file", RelinCombineCombinedR1(), c1.empty() });
        }

        auto missing = ValidateFields(required);
        if (!missing.empty())
        {
            RelinCombineResultBorder().Visibility(Visibility::Visible);
            RelinCombineResultText().Text(FormatMissingMessage(missing));
            return;
        }

        ::JuLennyFHE::Services::RelinCombineOptions opts;
        opts.round = round;
        opts.share_a_path = std::filesystem::path{ a };
        opts.share_b_path = std::filesystem::path{ b };
        opts.output_path  = std::filesystem::path{ out };
        opts.context_spec = m_context_spec;

        if (round == 1)
        {
            opts.joint_pk_path = std::filesystem::path{ jpk };
        }
        else
        {
            opts.combined_r1_path = std::filesystem::path{ c1 };
        }

        RelinCombineResultBorder().Visibility(Visibility::Visible);
        RelinCombineResultText().Text(L"Combining relinearization-key contributions...");
        RelinCombineGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.RelinCombine(opts);

        RelinCombineResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        RelinCombineGoButton().IsEnabled(true);
    }

    // --- Wrap upload (sign envelope) screen ---

    fire_and_forget MainWindow::OnWrapEnvelopePayloadBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) WrapEnvelopePayloadFile().Text(file.Path());
    }

    fire_and_forget MainWindow::OnWrapEnvelopeSecretKeyBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) WrapEnvelopeSecretKeyFile().Text(file.Path());
    }

    fire_and_forget MainWindow::OnWrapEnvelopeOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"upload");
        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".json");
        picker.FileTypeChoices().Insert(L"Signed JSON envelope", extensions);
        auto file = co_await picker.PickSaveFileAsync();
        if (file) WrapEnvelopeOutputFile().Text(file.Path());
    }

    void MainWindow::OnWrapEnvelopeGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto payload = std::wstring{ WrapEnvelopePayloadFile().Text() };
        auto sk      = std::wstring{ WrapEnvelopeSecretKeyFile().Text() };
        auto out     = std::wstring{ WrapEnvelopeOutputFile().Text() };
        auto perm    = std::wstring{ WrapEnvelopePermissionId().Text() };
        auto round_s = std::wstring{ WrapEnvelopeRound().Text() };

        // Message type: try .Text() first (works for typed input on an
        // editable ComboBox). If empty, fall back to SelectedItem - which
        // works when the user picked from the dropdown without typing.
        std::wstring msg_type_w{ WrapEnvelopeMessageType().Text() };
        if (msg_type_w.empty())
        {
            if (auto item = WrapEnvelopeMessageType().SelectedItem().try_as<Controls::ComboBoxItem>())
            {
                auto content = winrt::unbox_value_or<winrt::hstring>(item.Content(), L"");
                msg_type_w = std::wstring{ content };
            }
        }

        auto missing = ValidateFields({
            { L"Binary share file",     WrapEnvelopePayloadFile(),    payload.empty()    },
            { L"Signing secret key",    WrapEnvelopeSecretKeyFile(),  sk.empty()         },
            { L"Output .json path",     WrapEnvelopeOutputFile(),     out.empty()        },
            { L"Permission ID",         WrapEnvelopePermissionId(),   perm.empty()       },
            { L"Round",                 WrapEnvelopeRound(),          round_s.empty()    },
            { L"Message type",          WrapEnvelopeMessageType(),    msg_type_w.empty() },
        });
        if (!missing.empty())
        {
            WrapEnvelopeResultBorder().Visibility(Visibility::Visible);
            WrapEnvelopeResultText().Text(FormatMissingMessage(missing));
            return;
        }

        int round = 0;
        try
        {
            round = std::stoi(round_s);
        }
        catch (...)
        {
            WrapEnvelopeResultBorder().Visibility(Visibility::Visible);
            WrapEnvelopeResultText().Text(L"Round must be a positive integer (1, 2, 3, ...).");
            return;
        }
        if (round < 1)
        {
            WrapEnvelopeResultBorder().Visibility(Visibility::Visible);
            WrapEnvelopeResultText().Text(L"Round must be a positive integer (1, 2, 3, ...).");
            return;
        }

        ::JuLennyFHE::Services::WrapEnvelopeOptions opts;
        opts.payload_path    = std::filesystem::path{ payload };
        opts.secret_key_path = std::filesystem::path{ sk };
        opts.output_path     = std::filesystem::path{ out };
        opts.permission_id   = narrow(perm);
        opts.round           = round;
        opts.message_type    = narrow(msg_type_w);

        WrapEnvelopeResultBorder().Visibility(Visibility::Visible);
        WrapEnvelopeResultText().Text(L"Wrapping and signing...");
        WrapEnvelopeGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.WrapEnvelope(opts);

        WrapEnvelopeResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        WrapEnvelopeGoButton().IsEnabled(true);
    }

    // --- Wrap final keys (sign finalization envelope) screen ---

    fire_and_forget MainWindow::OnWrapFinalKeysToSignBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".json");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) WrapFinalKeysToSignFile().Text(file.Path());
    }

    fire_and_forget MainWindow::OnWrapFinalKeysSecretKeyBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) WrapFinalKeysSecretKeyFile().Text(file.Path());
    }

    fire_and_forget MainWindow::OnWrapFinalKeysOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"final-keys-signed-envelope");
        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".json");
        picker.FileTypeChoices().Insert(L"Signed final-keys JSON envelope", extensions);
        auto file = co_await picker.PickSaveFileAsync();
        if (file) WrapFinalKeysOutputFile().Text(file.Path());
    }

    void MainWindow::OnWrapFinalKeysGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto to_sign = std::wstring{ WrapFinalKeysToSignFile().Text() };
        auto sk      = std::wstring{ WrapFinalKeysSecretKeyFile().Text() };
        auto out     = std::wstring{ WrapFinalKeysOutputFile().Text() };

        auto missing = ValidateFields({
            { L"To-sign JSON file",  WrapFinalKeysToSignFile(),    to_sign.empty() },
            { L"Signing secret key", WrapFinalKeysSecretKeyFile(), sk.empty()      },
            { L"Output .json path",  WrapFinalKeysOutputFile(),    out.empty()     },
        });
        if (!missing.empty())
        {
            WrapFinalKeysResultBorder().Visibility(Visibility::Visible);
            WrapFinalKeysResultText().Text(FormatMissingMessage(missing));
            return;
        }

        ::JuLennyFHE::Services::WrapFinalKeysEnvelopeOptions opts;
        opts.to_sign_path    = std::filesystem::path{ to_sign };
        opts.secret_key_path = std::filesystem::path{ sk };
        opts.output_path     = std::filesystem::path{ out };

        WrapFinalKeysResultBorder().Visibility(Visibility::Visible);
        WrapFinalKeysResultText().Text(L"Wrapping and signing...");
        WrapFinalKeysGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.WrapFinalKeysEnvelope(opts);

        WrapFinalKeysResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        WrapFinalKeysGoButton().IsEnabled(true);
    }

    // --- Top-bar scheme picker ---
    //
    // Every operation panel reads m_context_spec when building its
    // ToolkitClient options struct, so switching here changes the active
    // context for all subsequent Go clicks.
    void MainWindow::OnSchemeChanged(IInspectable const&,
                                      Controls::SelectionChangedEventArgs const&)
    {
        try
        {
            auto combo = SchemeComboBox();
            if (!combo) return;
            auto sel = combo.SelectedItem().try_as<Controls::ComboBoxItem>();
            if (!sel) return;
            auto tag = winrt::unbox_value_or<winrt::hstring>(sel.Tag(), L"bfv-default-v1");
            std::wstring tag_w{ tag };
            m_context_spec = narrow(tag_w);
        }
        catch (...) {}
    }

    // --- Rotation combine screen ---

    fire_and_forget MainWindow::OnRotCombineShareABrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RotCombineShareA().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRotCombineShareBBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RotCombineShareB().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRotCombineJointPkBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RotCombineJointPk().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRotCombineOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"rotation_key");
        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".bin");
        picker.FileTypeChoices().Insert(L"Binary", extensions);
        auto file = co_await picker.PickSaveFileAsync();
        if (file) RotCombineOutput().Text(file.Path());
    }

    void MainWindow::OnRotCombineGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto a   = std::wstring{ RotCombineShareA().Text() };
        auto b   = std::wstring{ RotCombineShareB().Text() };
        auto jpk = std::wstring{ RotCombineJointPk().Text() };
        auto out = std::wstring{ RotCombineOutput().Text() };

        auto missing = ValidateFields({
            { L"Share A",          RotCombineShareA(),   a.empty()   },
            { L"Share B",          RotCombineShareB(),   b.empty()   },
            { L"Joint public key", RotCombineJointPk(),  jpk.empty() },
            { L"Output file",      RotCombineOutput(),   out.empty() },
        });
        if (!missing.empty())
        {
            RotCombineResultBorder().Visibility(Visibility::Visible);
            RotCombineResultText().Text(FormatMissingMessage(missing));
            return;
        }

        RotCombineResultBorder().Visibility(Visibility::Visible);
        RotCombineResultText().Text(L"Combining rotation-key contributions...");
        RotCombineGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::RotationCombineOptions opts;
        opts.share_a_path  = std::filesystem::path{ a };
        opts.share_b_path  = std::filesystem::path{ b };
        opts.joint_pk_path = std::filesystem::path{ jpk };
        opts.output_path   = std::filesystem::path{ out };
        opts.context_spec  = m_context_spec;

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.RotationCombine(opts);

        RotCombineResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        RotCombineGoButton().IsEnabled(true);
    }

    // --- Rotation contribute screen ---

    void MainWindow::OnRotContributeRoleChanged(IInspectable const&,
                                                 Controls::SelectionChangedEventArgs const&)
    {
        try
        {
            auto fields = RotContributeMainFields();
            auto combo  = RotContributeRole();
            if (!fields || !combo) return;
            auto sel = combo.SelectedItem().try_as<Controls::ComboBoxItem>();
            if (!sel) { fields.Visibility(Visibility::Collapsed); return; }
            auto tag = winrt::unbox_value_or<winrt::hstring>(sel.Tag(), L"");
            fields.Visibility(std::wstring{ tag } == L"main" ? Visibility::Visible : Visibility::Collapsed);
        }
        catch (...) {}
    }

    fire_and_forget MainWindow::OnRotContributeSecretKeyBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RotContributeSecretKey().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRotContributePeerShareBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RotContributePeerShare().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRotContributeJointPkBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileOpenPicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.FileTypeFilter().Append(L".bin");
        picker.FileTypeFilter().Append(L"*");
        auto file = co_await picker.PickSingleFileAsync();
        if (file) RotContributeJointPk().Text(file.Path());
    }

    fire_and_forget MainWindow::OnRotContributeOutputBrowseClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto lifetime = get_strong();
        FileSavePicker picker;
        AssociatePickerWithWindow(reinterpret_cast<::IInspectable*>(winrt::get_abi(picker)), *this);
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(L"rotation_contribution");
        auto extensions = winrt::single_threaded_vector<hstring>();
        extensions.Append(L".bin");
        picker.FileTypeChoices().Insert(L"Binary", extensions);
        auto file = co_await picker.PickSaveFileAsync();
        if (file) RotContributeOutput().Text(file.Path());
    }

    void MainWindow::OnRotContributeGoClicked(IInspectable const&, RoutedEventArgs const&)
    {
        auto role_item = RotContributeRole().SelectedItem().try_as<Controls::ComboBoxItem>();
        auto sk      = std::wstring{ RotContributeSecretKey().Text() };
        auto out     = std::wstring{ RotContributeOutput().Text() };
        auto indices = std::wstring{ RotContributeIndices().Text() };

        std::wstring role_w;
        if (role_item)
        {
            auto role_tag = winrt::unbox_value_or<winrt::hstring>(role_item.Tag(), L"");
            role_w = std::wstring{ role_tag };
        }
        const bool is_main = (role_w == L"main");
        auto peer = std::wstring{ RotContributePeerShare().Text() };
        auto jpk  = std::wstring{ RotContributeJointPk().Text() };

        std::vector<RequiredField> required = {
            { L"Role",              RotContributeRole(),       !role_item        },
            { L"Rotation indices",  RotContributeIndices(),    indices.empty()   },
            { L"Secret key",        RotContributeSecretKey(),  sk.empty()        },
            { L"Output file",       RotContributeOutput(),     out.empty()       },
        };
        if (is_main)
        {
            required.push_back({ L"Peer's contribution", RotContributePeerShare(), peer.empty() });
            required.push_back({ L"Joint public key",    RotContributeJointPk(),   jpk.empty()  });
        }
        auto missing = ValidateFields(required);
        if (!missing.empty())
        {
            RotContributeResultBorder().Visibility(Visibility::Visible);
            RotContributeResultText().Text(FormatMissingMessage(missing));
            return;
        }

        ::JuLennyFHE::Services::RotationContributeOptions opts;
        opts.role = narrow(role_w);
        opts.secret_key_path = std::filesystem::path{ sk };
        opts.output_path     = std::filesystem::path{ out };
        opts.context_spec    = m_context_spec;
        // Indices are a narrow ASCII csv (digits, minus, commas). Safe to
        // transcode by-byte from wstring; the parse runs in ToolkitClient.
        opts.indices_csv = narrow(indices);

        if (is_main)
        {
            opts.peer_share_path = std::filesystem::path{ peer };
            opts.joint_pk_path   = std::filesystem::path{ jpk };
        }

        RotContributeResultBorder().Visibility(Visibility::Visible);
        RotContributeResultText().Text(L"Computing rotation-key contribution...");
        RotContributeGoButton().IsEnabled(false);

        ::JuLennyFHE::Services::ToolkitClient client;
        auto result = client.RotationContribute(opts);

        RotContributeResultText().Text(result.success ? result.summary : (L"Error: " + result.error));
        RotContributeGoButton().IsEnabled(true);
    }
}
