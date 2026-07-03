#pragma once

#include <unknwn.h>
#include <restrictederrorinfo.h>
#include <hstring.h>

// clang-cl preprocessor strictness vs. Win32 macros:
// winbase.h defines GetCurrentTime() as a function-like macro that expands
// to GetTickCount(). CppWinRT generates a method also named GetCurrentTime
// in Microsoft.UI.Xaml.Media.Animation; clang-cl tries to expand the macro
// inside the method declaration and dies. MSVC happens to be lenient here.
// Undef before pulling in any WinRT headers.
#undef GetCurrentTime

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.ApplicationModel.Activation.h>

#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>
#include <winrt/Microsoft.UI.Xaml.Controls.Primitives.h>
#include <winrt/Microsoft.UI.Xaml.Data.h>
#include <winrt/Microsoft.UI.Xaml.Interop.h>
#include <winrt/Microsoft.UI.Xaml.Markup.h>
#include <winrt/Microsoft.UI.Xaml.Media.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>
#include <winrt/Microsoft.UI.Xaml.Shapes.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.h>
#include <winrt/Microsoft.UI.Windowing.h>

#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Storage.Pickers.h>

// File picker HWND init - WinUI 3 packaged apps need to associate the
// picker with the host window's HWND before showing.
#include <microsoft.ui.xaml.window.h>
#include <shobjidl.h>

// Microsoft.UI free functions (GetWindowIdFromWindow / GetWindowFromWindowId).
// Required to bridge a raw HWND to a Microsoft.UI.WindowId so we can fetch the
// AppWindow and call Resize/Move on it.
//
// Use the C++/WinRT projection (winrt/...) variant. The non-winrt
// Microsoft.UI.Interop.h transitively #includes <Microsoft.UI.h>, which is
// NOT shipped in WindowsAppSDK 1.5; the winrt/ variant goes through
// <winrt/Microsoft.UI.h>, which IS generated into "Generated Files".
#include <winrt/Microsoft.UI.Interop.h>

#include <wil/cppwinrt.h>
#include <wil/resource.h>

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
