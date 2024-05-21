// Torsten Sadowski
// SPDX-License-Identifier:  GPL-3.0-or-later

use crate::pwm_settings::{
    LeetError, PwmSetting, PwmSettings, PwmSettingsAccess, PwmSettingsError,
};
use digest::Digest;
use md4;
use md5;
use passwordmaker_rs::{
    HashAlgorithm, Hasher, HasherList, LeetLevel, PasswordMaker, UseLeetWhenGenerating,
    UseLeetWhenGeneratingDiscriminants,
};
use ripemd;
use sha1;
use sha2;
use slint::SharedString;
use std::{
    env::{var, VarError},
    fs::{self, File},
    io::Write,
    str::FromStr,
};
use strum_macros::Display;

pub struct Md4;
pub struct Md5;
pub struct Sha1;
pub struct Sha256;
pub struct RipeMD160;
impl Hasher for Md4 {
    type Output = [u8; 16];
    fn hash(data: &[u8]) -> Self::Output {
        md4::Md4::digest(data).into()
    }
}
impl Hasher for Md5 {
    type Output = [u8; 16];
    fn hash(data: &[u8]) -> Self::Output {
        md5::Md5::digest(data).into()
    }
}
impl Hasher for Sha1 {
    type Output = [u8; 20];
    fn hash(data: &[u8]) -> Self::Output {
        sha1::Sha1::digest(data).into()
    }
}
impl Hasher for Sha256 {
    type Output = [u8; 32];
    fn hash(data: &[u8]) -> Self::Output {
        sha2::Sha256::digest(data).into()
    }
}
impl Hasher for RipeMD160 {
    type Output = [u8; 20];
    fn hash(data: &[u8]) -> Self::Output {
        ripemd::Ripemd160::digest(data).into()
    }
}

impl passwordmaker_rs::Md4 for Md4 {}
impl passwordmaker_rs::Md5 for Md5 {}
impl passwordmaker_rs::Sha1 for Sha1 {}
impl passwordmaker_rs::Sha256 for Sha256 {}
impl passwordmaker_rs::Ripemd160 for RipeMD160 {}

pub struct Hashes {}
impl HasherList for Hashes {
    type MD4 = Md4;
    type MD5 = Md5;
    type SHA1 = Sha1;
    type SHA256 = Sha256;
    type RIPEMD160 = RipeMD160;
}

#[derive(Debug, Clone, Copy, Display)]
pub enum PwmConfigError {
    Ok,
    NoHome,
    NoLock,
    NoApp,
    FailOpenForWrite,
    FailWrite,
    FailOpenForRead,
    FailRead,
    Str2Toml,
}

pub struct PwmGuiData {
    settings: PwmSettings,
    settings_error: PwmSettingsError,
    error: PwmConfigError,
}

pub type Pwm<'a> = PasswordMaker<'a, Hashes>;

pub fn master_verification(master: String) -> String {
    let pwm = Pwm::new(
        HashAlgorithm::Sha256,
        passwordmaker_rs::UseLeetWhenGenerating::NotAtAll,
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "",
        "",
        3,
        "",
        "",
    )
    .unwrap();
    let result = pwm.generate(" ".to_owned(), master.to_owned());
    match result {
        Ok(verification) => return verification,
        Err(error) => return error.to_string(),
    }
}

fn get_home_dir() -> Result<String, VarError> {
    match var("XDG_CONFIG_HOME") {
        Ok(config_dir) => return Ok(config_dir),
        Err(_e) => match var("HOME") {
            Ok(home) => Ok(format!("{}/.config", home)),
            Err(e) => Err(e),
        },
    }
}

fn create_use_leet_when_generating(
    use_leet: &str,
    leet_level: &str,
) -> Result<UseLeetWhenGenerating, LeetError> {
    let ll = LeetLevel::from_str(leet_level);
    let uldr: Result<UseLeetWhenGeneratingDiscriminants, _> =
        UseLeetWhenGeneratingDiscriminants::from_str(use_leet);
    match uldr {
        Ok(u) => match u {
            UseLeetWhenGeneratingDiscriminants::NotAtAll => Ok(UseLeetWhenGenerating::NotAtAll),
            UseLeetWhenGeneratingDiscriminants::Before if ll.is_ok() => {
                Ok(UseLeetWhenGenerating::Before { level: ll.unwrap() })
            }
            UseLeetWhenGeneratingDiscriminants::After if ll.is_ok() => {
                Ok(UseLeetWhenGenerating::After { level: ll.unwrap() })
            }
            UseLeetWhenGeneratingDiscriminants::BeforeAndAfter if ll.is_ok() => {
                Ok(UseLeetWhenGenerating::BeforeAndAfter { level: ll.unwrap() })
            }
            _ => return Err(LeetError::ParseLeetLevelError),
        },
        Err(_e) => return Err(LeetError::ParseUseLeetError),
    }
}

pub trait PwmGui<'a> {
    fn new() -> Self;
    fn create_settings(&mut self);
    fn load_settings(&mut self) -> Result<(), PwmConfigError>;
    fn save_settings(&mut self) -> Result<(), PwmConfigError>;
    fn pwm_from_setting(&'a mut self) -> Result<Pwm<'a>, PwmSettingsError>;
    fn create_password(&mut self, url: String, master: String) -> String;
    fn add_setting(&mut self);
    fn delete_setting(&mut self);
    fn get_current_setting(&self) -> usize;
    fn set_current_setting(&mut self, current_setting: usize);
    fn get_current_setting_data(&self) -> &PwmSetting;
    fn set_current_setting_data(&mut self, setting_data: PwmSetting);
    fn get_setting_names(&self) -> Vec<SharedString>;
}

impl<'a> PwmGui<'a> for PwmGuiData {
    fn new() -> Self {
        PwmGuiData {
            settings: PwmSettings::new(),
            settings_error: PwmSettingsError::Ok,
            error: PwmConfigError::Ok,
        }
    }

    fn create_settings(&mut self) {
        self.settings.add_setting();
        self.settings_error = match self.pwm_from_setting() {
            Ok(_) => {
                return;
            }
            Err(e) => e,
        }
    }

    fn load_settings(&mut self) -> Result<(), PwmConfigError> {
        let home = match get_home_dir() {
            Ok(home) => home,
            Err(_) => {
                self.create_settings();
                return Err(PwmConfigError::NoHome);
            }
        };
        let path = format!("{}/passwordmaker.toml", home);
        let vec_u8 = match fs::read(path) {
            Ok(vec_u8) => vec_u8,
            Err(_) => {
                self.create_settings();
                return Err(PwmConfigError::FailOpenForRead);
            }
        };
        let setstr = match std::str::from_utf8(vec_u8.as_slice()) {
            Ok(setstr) => setstr,
            Err(_) => {
                self.create_settings();
                return Err(PwmConfigError::FailRead);
            }
        };
        self.settings = match toml::from_str(setstr) {
            Ok(settings) => settings,
            Err(_) => {
                self.create_settings();
                return Err(PwmConfigError::Str2Toml);
            }
        };
        Ok(())
    }

    fn save_settings(&mut self) -> Result<(), PwmConfigError> {
        let home = match get_home_dir() {
            Ok(home) => home,
            Err(_e) => {
                self.error = PwmConfigError::NoHome;
                return Err(self.error);
            }
        };
        let toml = toml::to_string(&self.settings).unwrap();
        let path = format!("{}/passwordmaker.toml", home);

        let mut output = match File::create(path) {
            Ok(output) => output,
            Err(_e) => {
                self.error = PwmConfigError::FailOpenForWrite;
                return Err(self.error);
            }
        };
        match write!(output, "{}", toml) {
            Ok(_) => Ok(()),
            Err(_) => {
                self.error = PwmConfigError::FailWrite;
                Err(self.error)
            }
        }
    }

    fn pwm_from_setting(&'a mut self) -> Result<Pwm<'a>, PwmSettingsError> {
        let setting = self.settings.get_current_setting_data();
        let hash_algo = match HashAlgorithm::from_str(&setting.hash_algorithm) {
            Ok(hash_algo) => hash_algo,
            Err(e) => return Err(PwmSettingsError::HashAlgorithmError { error: e }),
        };
        let use_leet = match create_use_leet_when_generating(&setting.use_leet, &setting.leet_level)
        {
            Ok(use_leet) => use_leet,
            Err(e) => return Err(PwmSettingsError::LeetError { error: e }),
        };
        let pwm = match Pwm::new(
            hash_algo,
            use_leet,
            &setting.characters,
            &setting.username,
            &setting.modifier,
            setting.password_length,
            &setting.prefix,
            &setting.suffix,
        ) {
            Ok(pwm) => Ok(pwm),
            Err(e) => Err(PwmSettingsError::SettingsError { error: e }),
        };
        pwm
    }

    fn create_password(&mut self, url: String, master: String) -> String {
        match self.pwm_from_setting() {
            Ok(pwm) => match pwm.generate(url, master) {
                Ok(pw) => pw,
                Err(e) => e.to_string(),
            },
            Err(e) => e.to_string(),
        }
    }
    fn add_setting(&mut self) {
        self.settings.add_setting();
    }
    fn delete_setting(&mut self) {
        self.settings.delete_setting();
    }
    fn get_current_setting(&self) -> usize {
        self.settings.get_current_setting()
    }
    fn set_current_setting(&mut self, current_setting: usize) {
        self.settings.set_current_setting(current_setting)
    }
    fn get_current_setting_data(&self) -> &PwmSetting {
        self.settings.get_current_setting_data()
    }
    fn set_current_setting_data(&mut self, setting_data: PwmSetting) {
        self.settings.set_current_setting_data(setting_data)
    }
    fn get_setting_names(&self) -> Vec<SharedString> {
        self.settings.get_setting_names()
    }
}
