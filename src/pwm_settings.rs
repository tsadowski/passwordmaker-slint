slint::include_modules!();

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use slint::SharedString;

#[derive(Clone, Serialize, Deserialize)]
pub struct PwmSetting {
    pub name: String,
    pub hash_algorithm: String,
    pub use_leet: String,
    pub leet_level: String,
    pub characters: String,
    pub username: String,
    pub modifier: String,
    pub password_length: usize,
    pub prefix: String,
    pub suffix: String,
    pub use_domain: bool,
    pub use_subdomain: bool,
    pub use_protocol: bool,
    pub use_params: bool,
    pub use_userinfo: bool,
}

#[derive(Serialize, Deserialize)]
pub struct PwmSettings {
    settings: Vec<PwmSetting>,
    current_setting: usize,
}

pub trait PwmSettingsAccess {
    fn new() -> Self;
    fn add_setting(&mut self);
    fn delete_setting(&mut self);
    fn get_current_setting(&self) -> usize;
    fn set_current_setting(&mut self, current: usize);
    fn get_current_setting_data(&self) -> &PwmSetting;
    fn set_current_setting_data(&mut self, setting: PwmSetting);
    fn get_setting_names(&self) -> Vec<SharedString>;
}

impl PwmSettingsAccess for PwmSettings {
    fn new() -> Self {
        let ps = PwmSettings {
            settings: Vec::new(),
            current_setting: 0,
        };
        ps
    }
    fn add_setting(&mut self) {
        self.settings
            .push(once_cell::sync::Lazy::<PwmSetting>::force(&PWM_DEFAULT).clone());
        self.current_setting = self.settings.len() - 1;
    }
    fn delete_setting(&mut self) {
        if self.settings.is_empty() {
            return;
        };
        if self.current_setting >= self.settings.len() {
            self.current_setting = self.settings.len() - 1;
        }
        self.settings.remove(self.current_setting);
        if self.current_setting >= self.settings.len() {
            self.current_setting = self.settings.len() - 1;
        }
    }
    fn get_current_setting(&self) -> usize {
        self.current_setting
    }
    fn set_current_setting(&mut self, current: usize) {
        self.current_setting = if current < self.settings.len() {
            current
        } else {
            self.settings.len() - 1
        }
    }
    fn get_current_setting_data(&self) -> &PwmSetting {
        match self.settings.get(self.current_setting) {
            Some(pwms) => pwms,
            None => once_cell::sync::Lazy::<PwmSetting>::force(&PWM_DEFAULT),
        }
    }
    fn set_current_setting_data(&mut self, setting: PwmSetting) {
        match self.settings.get_mut(self.current_setting) {
            Some(pwms) => *pwms = setting,
            None => return,
        }
    }
    fn get_setting_names(&self) -> Vec<SharedString> {
        Vec::from_iter(
            self.settings
                .clone()
                .into_iter()
                .map(|s| SharedString::from(s.name.clone())),
        )
    }
}

pub static PWM_DEFAULT: Lazy<PwmSetting> = Lazy::new(|| {
    let pwm = PwmSetting {
        name: String::from("default"),
    hash_algorithm: String::from("Md5"),
    use_leet: String::from("NotAtAll"),
    leet_level: String::from(""),
    characters: String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`~!@#$%^&*()_-+={}|[]\\:\";'<>?,./"),
    username: String::from(""),
    modifier: String::from(""),
    password_length: 8,
    prefix: String::from(""), 
    suffix: String::from(""),
    use_domain: true,
    use_subdomain: true,
    use_protocol: false,
    use_params: false,
    use_userinfo: false
    };
    pwm
});
