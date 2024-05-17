// Torsten Sadowski
// SPDX-License-Identifier:  GPL-3.0-or-later

slint::include_modules!();

mod pwm_settings;
use crate::pwm_settings::{PwmSetting, PwmSettings, PwmSettingsAccess, PWM_DEFAULT};

use once_cell::sync::Lazy;
use std::{
    env::{var, VarError},
    fs::{self, File},
    io::Write,
    rc::Rc,
    str::FromStr,
    sync::Mutex,
    vec::Vec,
};
use strum::{ParseError, VariantNames};
use strum_macros::Display;

use slint::{ModelRc, SharedString, VecModel};

use digest::Digest;
use md4;
use md5;
use passwordmaker_rs::{
    HashAlgorithm, Hasher, HasherList, LeetLevel, PasswordMaker, ProtocolUsageMode, SettingsError,
    UrlParsing, UseLeetWhenGenerating, UseLeetWhenGeneratingDiscriminants,
};
use ripemd;
use sha1;
use sha2;

enum LeetError {
    ParseLeetLevelError,
    ParseUseLeetError,
}

#[derive(Display)]
enum PwmSettingsError {
    Ok,
    HashAlgorithmError { error: ParseError },
    LeetError { error: LeetError },
    SettingsError { error: SettingsError },
}

#[derive(Debug, Clone, Copy, Display)]
enum PwmConfigError {
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

static PWM_DATA: Lazy<Mutex<PwmGuiData>> = Lazy::new(|| {
    Mutex::new({
        let pgdata = PwmGuiData::new();
        pgdata
    })
});

struct Md4;
struct Md5;
struct Sha1;
struct Sha256;
struct RipeMD160;
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

struct Hashes {}
impl HasherList for Hashes {
    type MD4 = Md4;
    type MD5 = Md5;
    type SHA1 = Sha1;
    type SHA256 = Sha256;
    type RIPEMD160 = RipeMD160;
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

struct PwmGuiData {
    settings: PwmSettings,
    settings_error: PwmSettingsError,
    error: PwmConfigError,
}

trait PwmGui<'a> {
    fn new() -> Self;
    fn create_settings(&mut self);
    fn load_settings(&mut self) -> Result<(), PwmConfigError>;
    fn save_settings(&mut self) -> Result<(), PwmConfigError>;
    fn pwm_from_setting(&'a mut self) -> Result<Pwm<'a>, PwmSettingsError>;
    fn create_password(&mut self, url: String, master: String) -> String;
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
}

type Pwm<'a> = PasswordMaker<'a, Hashes>;

fn master_verification(master: String) -> String {
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

impl From<PwmSlintSetting> for PwmSetting {
    fn from(item: PwmSlintSetting) -> PwmSetting {
        PwmSetting {
            name: item.name.into(),
            hash_algorithm: item.hash_algorithm.into(),
            use_leet: item.use_leet.into(),
            leet_level: item.leet_level.into(),
            characters: item.characters.into(),
            username: item.username.into(),
            modifier: item.modifier.into(),
            password_length: match item.password_length.try_into() {
                Ok(pwl) => pwl,
                Err(_) => 0,
            },
            prefix: item.prefix.into(),
            suffix: item.suffix.into(),
            use_domain: item.use_domain,
            use_subdomain: item.use_subdomain,
            use_protocol: item.use_protocol,
            use_params: item.use_params,
            use_userinfo: item.use_userinfo,
        }
    }
}

impl From<PwmSetting> for PwmSlintSetting {
    fn from(item: PwmSetting) -> PwmSlintSetting {
        PwmSlintSetting {
            name: item.name.into(),
            hash_algorithm: item.hash_algorithm.into(),
            use_leet: item.use_leet.into(),
            leet_level: item.leet_level.into(),
            characters: item.characters.into(),
            username: item.username.into(),
            modifier: item.modifier.into(),
            password_length: match item.password_length.try_into() {
                Ok(pwl) => pwl,
                Err(_) => 0,
            },
            prefix: item.prefix.into(),
            suffix: item.suffix.into(),
            use_domain: item.use_domain,
            use_subdomain: item.use_subdomain,
            use_protocol: item.use_protocol,
            use_params: item.use_params,
            use_userinfo: item.use_userinfo,
        }
    }
}

fn on_url_edited(url: SharedString) -> SharedString {
    let pwm = match PWM_DATA.lock() {
        Ok(pwm) => pwm,
        Err(_) => return SharedString::from("No Lock!"),
    };
    let use_protocol = if pwm.settings.get_current_setting_data().use_protocol {
        ProtocolUsageMode::Used
    } else {
        ProtocolUsageMode::Ignored
    };
    let urlparse = UrlParsing::new(
        use_protocol,
        pwm.settings.get_current_setting_data().use_userinfo,
        pwm.settings.get_current_setting_data().use_subdomain,
        pwm.settings.get_current_setting_data().use_domain,
        pwm.settings.get_current_setting_data().use_params,
    );
    urlparse.parse(url.as_str()).into()
}

fn on_used_text_edited(url: SharedString, master: SharedString) -> SharedString {
    match PWM_DATA.lock() {
        Ok(mut pwm) => pwm
            .create_password(url.to_string(), master.to_string())
            .into(),
        Err(_) => SharedString::from("No Lock!"),
    }
}

fn on_pw_edited(master: SharedString) -> SharedString {
    master_verification(master.to_string()).into()
}

fn on_get_current_setting() -> i32 {
    match PWM_DATA.lock() {
        Ok(pwm) => match pwm.settings.get_current_setting().try_into() {
            Ok(cs) => cs,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

fn on_set_current_setting(current_setting: i32) {
    match PWM_DATA.lock() {
        Ok(mut pwm) => match current_setting.try_into() {
            Ok(cs) => pwm.settings.set_current_setting(cs),
            Err(_) => pwm.settings.set_current_setting(0),
        },
        Err(_) => (),
    }
}

fn on_get_available_settings() -> ModelRc<SharedString> {
    let setting_names = match PWM_DATA.lock() {
        Ok(pwm) => pwm.settings.get_setting_names(),
        Err(_) => Vec::<SharedString>::new(),
    };
    let vm_setting_names = VecModel::from(setting_names);
    ModelRc::from(Rc::new(vm_setting_names))
}

fn on_model_add_setting() {
    match PWM_DATA.lock() {
        Err(_) => return,
        Ok(mut pwm) => {
            pwm.settings.add_setting();
        }
    }
}

fn on_model_delete_setting() {
    match PWM_DATA.lock() {
        Err(_) => return,
        Ok(mut pwm) => {
            pwm.settings.delete_setting();
        }
    }
}

fn on_get_setting_data() -> PwmSlintSetting {
    match PWM_DATA.lock() {
        Ok(pwm) => pwm.settings.get_current_setting_data().clone().into(),
        Err(_) => PWM_DEFAULT.clone().into(),
    }
}

fn on_set_setting_data(setting: PwmSlintSetting) {
    match PWM_DATA.lock() {
        Ok(mut pwm) => pwm.settings.set_current_setting_data(setting.into()),
        Err(_) => return,
    }
}

fn get_vecmodel_from_enum(enum_variant_names: &[&str]) -> ModelRc<SharedString> {
    let enum_names = Vec::from_iter(
        enum_variant_names
            .into_iter()
            .map(|s| SharedString::from(*s)),
    );
    let vm_enum_names = VecModel::from(enum_names);
    ModelRc::from(Rc::new(vm_enum_names))
}

fn main() -> Result<(), PwmConfigError> {
    let _error = match PWM_DATA.lock() {
        Ok(mut pwm) => match pwm.load_settings() {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        },
        Err(_) => return Err(PwmConfigError::NoLock),
    };
    let app = match App::new() {
        Ok(app) => app,
        Err(_) => return Err(PwmConfigError::NoApp),
    };
    app.global::<UiSettings>()
        .set_hash_algorithms(get_vecmodel_from_enum(HashAlgorithm::VARIANTS));
    app.global::<UiSettings>()
        .set_use_leet(get_vecmodel_from_enum(UseLeetWhenGenerating::VARIANTS));
    app.global::<UiSettings>()
        .set_leet_level(get_vecmodel_from_enum(LeetLevel::VARIANTS));
    app.global::<UiSettings>()
        .set_current_setting(on_get_current_setting());
    app.global::<UiSettings>()
        .set_setting(on_get_setting_data());
    app.global::<UiSettings>()
        .set_available_settings(on_get_available_settings());
    app.global::<MakePageCallback>()
        .on_url_edited(|url| on_url_edited(url));
    app.global::<MakePageCallback>()
        .on_used_text_edited(|url, master| on_used_text_edited(url, master));
    app.global::<MakePageCallback>()
        .on_pw_edited(|master| on_pw_edited(master));
    app.global::<SettingsPageCallback>()
        .on_get_current_setting(|| on_get_current_setting());
    app.global::<SettingsPageCallback>()
        .on_set_current_setting(|cs| on_set_current_setting(cs));
    app.global::<SettingsPageCallback>()
        .on_get_available_settings(|| on_get_available_settings());
    app.global::<SettingsPageCallback>()
        .on_model_add_setting(|| on_model_add_setting());
    app.global::<SettingsPageCallback>()
        .on_model_delete_setting(|| on_model_delete_setting());
    app.global::<SettingsPageCallback>()
        .on_get_setting_data(|| on_get_setting_data());
    app.global::<SettingsPageCallback>()
        .on_set_setting_data(|setting| on_set_setting_data(setting));
    match app.run() {
        Ok(_) => (),
        Err(_) => return Err(PwmConfigError::NoApp),
    };
    match PWM_DATA.lock() {
        Ok(mut pwm) => pwm.save_settings(),
        Err(_) => Err(PwmConfigError::NoLock),
    }
}
