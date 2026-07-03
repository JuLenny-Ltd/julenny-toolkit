# Assets

Visual Studio's WinUI 3 project template generates the PNG assets referenced
by Package.appxmanifest:

    StoreLogo.png
    Square150x150Logo.png
    Square44x44Logo.png
    Wide310x150Logo.png
    SplashScreen.png
    LockScreenLogo.png

If you create the project from a template (recommended in windows/README.md),
these will be added automatically. If you scaffold by hand, copy the assets
from a fresh template project, or replace the manifest references with
existing icons.

These are not committed because they are binary template artifacts that
Visual Studio regenerates per project.
