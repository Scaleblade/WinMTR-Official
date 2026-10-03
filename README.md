# WinMTR-Official

Thank you for downloading WinMTR v0.92!

## About

WinMTR is a free Microsoft Windows visual application that combines the functionality of the traceroute and ping in a single network diagnostic tool. WinMTR is Open Source Software, (barely) maintained by Dragos Manac.

It was started in 2000 by Vasile Laurentiu Stanimir as a clone for the popular Matt's Traceroute (hence MTR) Linux/UNIX utility.

## License & Redistribution

WinMTR is offered as Open Source Software under GPL v2.

- [Read more about the licensing conditions](http://www.gnu.org/licenses/gpl-2.0.html)
- [Download the code](https://github.com/WinMTR/WinMTR-Official)

## Installation

You will get a `.zip` archive containing two folders: `WinMTR-32` and `WinMTR-64`. Both contain two files: `WinMTR.exe` and `README.md`.

Just extract the `WinMTR.exe` for your platform (32 or 64 bit) and click to run it. If you don't know what version you need, just click on both files and see which one works ;-)

As you can see, WinMTR requires no other installation effort.

**Tip:** You can copy `WinMTR.exe` to `Windows/System32` so it's accessible via the command line (cmd).

## Building from Source

Open `WinMTR.sln` with Visual Studio 2026 and install the **Desktop development with C++** workload, including the latest MSVC x86/x64 tools, a Windows SDK, and MFC for x86/x64.

You can also build from a Developer PowerShell prompt:

```powershell
msbuild WinMTR.sln /m /p:Configuration=Release /p:Platform=x64
```

Use `Win32` instead of `x64` to build the 32-bit application. Build artifacts are written to architecture-specific folders such as `Release_x64` and `Release_x32`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for commit message and pull request title conventions.

## Continuous Integration

The **Windows CI** workflow runs on pull requests targeting `main` and can be run manually from the Actions tab once it is on the default branch. It does not run on pushes or a schedule. It uses standard GitHub-hosted `windows-2025-vs2026` runners with Visual Studio 2026 and MFC; no paid or self-hosted runner is required for this public repository.

Four build checks rebuild the solution: **Build (Debug, Win32)**, **Build (Debug, x64)**, **Build (Release, Win32)**, and **Build (Release, x64)**. The `main` ruleset requires these four checks before merging. Fork maintainers can configure the same requirements after their first successful hosted run. Existing compiler warnings remain nonfatal.

Two separate checks, **Analyze (Release, Win32)** and **Analyze (Release, x64)**, run MSVC `/analyze`. Findings are advisory while the existing warning baseline is reviewed; keep these checks outside the required-check ruleset. Build or analyzer execution errors still fail their analysis job so broken checks remain visible.

To reproduce a build in a VS 2026 Developer PowerShell prompt, run:

```powershell
msbuild WinMTR.sln /t:Rebuild /m /p:Configuration=Debug /p:Platform=Win32
```

Use `Release` and/or `x64` to reproduce the other configurations. Close any running copy of the executable in the output folder before rebuilding. To reproduce analysis without permanently changing local compiler settings:

```powershell
$previousCl = $env:_CL_
try {
    $env:_CL_ = '/analyze /analyze:WX-'
    msbuild WinMTR.sln /t:Rebuild /m /p:Configuration=Release /p:Platform=x64
} finally {
    $env:_CL_ = $previousCl
}
```

Use `Win32` for the other analysis check. `_CL_` appends the flags after MSBuild's defaults, which otherwise disable analysis for Win32. Diagnostics appear in the build output and in `*.nativecodeanalysis.xml` reports.

Open a workflow run under **Actions → Windows CI** to download artifacts while signed in to GitHub. Successful Release builds provide `WinMTR-Release-Win32` and `WinMTR-Release-x64`, each containing `WinMTR.exe`. Build jobs retain text and binary logs, and analysis jobs retain logs and native-analysis reports, including available diagnostics after a failure. Artifacts expire after seven days. These are CI builds, not published releases.

CI verifies compilation, linking, and static analysis. It does not test the GUI or live network tracing. Formatting, clang-tidy, and regression tests are separate follow-up work.

## Usage

### Visual

1. Start WinMTR
2. Write the name or IP of the host (e.g. `github.com`)
3. Press the **Options** button to configure ping size, maximum hops and ping interval (the defaults are OK)
4. Push the **Start** button and wait
5. Copy or export the results in text or HTML format — useful if you want to document or file a complaint with your ISP
6. Click on **Clear History** to remove the hosts you have previously traced

Double-click a hostname or IP in the **Hostname** column to look up the hop's underlying IPv4 address on [bgp.tools](https://bgp.tools/) in your default browser. This works during tracing and after stopping. The first two hops, unanswered hops, and rows displaying diagnostic messages are skipped. Valid hops from row 3 onward can be looked up, including private IP addresses.

Double-click a statistics column during tracing to open the existing hop-details dialog.

### Command Line
```
winmtr [options] [host]
```

Command-line arguments configure the graphical application when it starts. A host argument pre-fills the destination, and `--help` opens the help dialog. Tracing and viewing results are done in the window; this version does not provide a command-line-only trace or text output.

The supported options are `--interval` (`-i`), `--size` (`-s`, 64–4096 bytes), `--maxLRU` (`-m`), and `--numeric` (`-n`, disables DNS lookups).

## Troubleshooting

**I type in the address and nothing happens.**
Usually this has to do with antivirus or firewall applications. Disable them when debugging or using WinMTR, or configure them properly.

**I get an error saying the program cannot be executed.**
You are running the 64-bit version on a 32-bit platform. Try the `WinMTR.exe` in the `WinMTR_x32` folder.

**I get an error not listed here.**
Please report it to us to make sure it's not a bug in the application.

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2025-11-26 | — | Homepage moved to WinMTR.net and development repository to GitHub. Still looking for developers. |
| 2011-01-31 | v0.92 | Fixed reporting errors for very slow connections |
| 2011-01-11 | v0.91 | Released under GPL v2 by popular request |
| 2010-12-24 | v0.9 | Support for 32 and 64 bit OS. Works on Windows 7 as regular user. Various bug fixes. |
| 2002-01-20 | — | Last entered hosts and options now stored in registry. Moved to SourceForge. |
| 2001-09-05 | v0.7 | Combo box for host history. Fixed memory leak causing crashes. |
| 2000-11-27 | v0.6 | Added resizing support and flat buttons |
| 2000-11-26 | v0.5 | Copy to clipboard, save as text/HTML |
| 2000-08-03 | v0.4 | Double-click host for detailed info |
| 2000-08-02 | v0.3 | Fixed ICMP error codes handling |
| 2000-08-01 | v0.2 | Full command-line support |
| 2000-07-28 | v0.1 | First release |

## Bug Reports

Let us know if you identify bugs. Please include:

- WinMTR version
- Operating System and setup details

Before submitting, make sure it's not related to your specific configuration (antivirus, firewalls, etc.).

## Feature Requests

If you need functionality that others could also benefit from, let us know. We'll try to integrate it in future releases.

If you're a developer planning to extend the code, please reach out so we can integrate it into the official tree.

## Contact

Email: contact AT winmtr DOT net
