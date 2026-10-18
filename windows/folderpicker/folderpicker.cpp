// folderpicker.dll - modern folder picker for the JuLenny Windows installer.
//
// Inno Setup's setup.exe runs as a 32-BIT process, so this DLL is built x86
// (see windows\build-folderpicker.ps1). It opens the modern Windows folder
// dialog (IFileOpenDialog in pick-folders mode: Quick Access, recent, pinned,
// address bar) instead of Inno's built-in legacy folder tree.
//
// Single export, called from the installer's [Code] section:
//   int ShowFolderDialog(const wchar_t* title, const wchar_t* initialPath,
//                        wchar_t* outBuf, int outBufChars)
// Returns the number of wide chars written to outBuf (0 on cancel/error).
// The export name is kept undecorated via folderpicker.def so Inno can bind it.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shobjidl.h>
#include <shlobj.h>

extern "C" __declspec(dllexport) int __stdcall ShowFolderDialog(
    const wchar_t* title,
    const wchar_t* initialPath,
    wchar_t* outBuf,
    int outBufChars)
{
    if (!outBuf || outBufChars <= 0) return 0;
    outBuf[0] = L'\0';

    const HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    const bool didInit = SUCCEEDED(hrInit);
    int written = 0;

    IFileOpenDialog* dlg = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&dlg));
    if (SUCCEEDED(hr) && dlg)
    {
        DWORD opts = 0;
        dlg->GetOptions(&opts);
        dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
        if (title && title[0]) dlg->SetTitle(title);

        // Start the dialog at the caller's current folder, if it exists.
        if (initialPath && initialPath[0])
        {
            IShellItem* startItem = nullptr;
            if (SUCCEEDED(SHCreateItemFromParsingName(initialPath, nullptr, IID_PPV_ARGS(&startItem))) && startItem)
            {
                dlg->SetFolder(startItem);
                startItem->Release();
            }
        }

        if (SUCCEEDED(dlg->Show(nullptr)))
        {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dlg->GetResult(&item)) && item)
            {
                PWSTR psz = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &psz)) && psz)
                {
                    int i = 0;
                    while (psz[i] && i < outBufChars - 1) { outBuf[i] = psz[i]; ++i; }
                    outBuf[i] = L'\0';
                    written = i;
                    CoTaskMemFree(psz);
                }
                item->Release();
            }
        }
        dlg->Release();
    }

    if (didInit) CoUninitialize();
    return written;
}
