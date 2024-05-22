# passwordmaker-slint
Rust and Slint GUI for the passwordmaker-rs library.

Settings are saved as passwordmaker.toml in ~/.config. The GUI is not extensively tested but works for me. It is mainly the same as the Qt version but the master password verification code was taken from the Android version. the code is not the same because the library does not allow empty strings to be hashed. But a single space is sufficient.
