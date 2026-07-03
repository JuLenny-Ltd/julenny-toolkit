#include "prompts.h"

#include <cstdio>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace julenny_fhe::cli {

namespace {

#ifdef _WIN32

// Hidden-input prompt against the real console (CONIN$/CONOUT$), so it works
// even when stdin/stdout are redirected - the Windows analogue of /dev/tty.
std::optional<std::string> prompt_interactive(const std::string& prompt) {
    HANDLE hin = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (hin == INVALID_HANDLE_VALUE) return std::nullopt;
    HANDLE hout = CreateFileA("CONOUT$", GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (hout == INVALID_HANDLE_VALUE) {
        CloseHandle(hin);
        return std::nullopt;
    }

    DWORD written = 0;
    WriteConsoleA(hout, prompt.c_str(), static_cast<DWORD>(prompt.size()),
                  &written, nullptr);

    DWORD old_mode = 0;
    if (!GetConsoleMode(hin, &old_mode)) {
        CloseHandle(hin);
        CloseHandle(hout);
        return std::nullopt;
    }
    // Drop echo, keep line buffering so Enter terminates the read.
    SetConsoleMode(hin, old_mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));

    std::string line;
    char ch = 0;
    DWORD read = 0;
    while (ReadConsoleA(hin, &ch, 1, &read, nullptr) && read == 1 && ch != '\n') {
        if (ch != '\r') line.push_back(ch);
    }

    SetConsoleMode(hin, old_mode);
    WriteConsoleA(hout, "\r\n", 2, &written, nullptr);
    CloseHandle(hin);
    CloseHandle(hout);

    return line;
}

#else

std::optional<std::string> prompt_interactive(const std::string& prompt) {
    FILE* tty = std::fopen("/dev/tty", "r+");
    if (!tty) return std::nullopt;

    std::fputs(prompt.c_str(), tty);
    std::fflush(tty);

    termios old_term;
    if (tcgetattr(fileno(tty), &old_term) != 0) {
        std::fclose(tty);
        return std::nullopt;
    }
    termios new_term = old_term;
    new_term.c_lflag = new_term.c_lflag & ~static_cast<tcflag_t>(ECHO);
    if (tcsetattr(fileno(tty), TCSAFLUSH, &new_term) != 0) {
        std::fclose(tty);
        return std::nullopt;
    }

    std::string line;
    int c;
    while ((c = std::fgetc(tty)) != EOF && c != '\n') {
        line.push_back(static_cast<char>(c));
    }

    tcsetattr(fileno(tty), TCSAFLUSH, &old_term);
    std::fputc('\n', tty);
    std::fclose(tty);

    return line;
}

#endif

}  // namespace

std::optional<std::string> resolve_passphrase(const std::string& explicit_arg,
                                              const std::string& prompt) {
    if (!explicit_arg.empty()) return explicit_arg;
    if (const char* env = std::getenv("FHE_TOOLKIT_PASSPHRASE"); env && env[0] != '\0') {
        return std::string(env);
    }
    return prompt_interactive(prompt);
}

}  // namespace julenny_fhe::cli
