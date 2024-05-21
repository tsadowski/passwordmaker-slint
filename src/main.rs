// Torsten Sadowski
// SPDX-License-Identifier:  GPL-3.0-or-later

slint::include_modules!();

mod pwm_gui_data;
mod pwm_settings;
use crate::pwm_gui_data::{master_verification, PwmConfigError, PwmGui, PwmGuiData};
use crate::pwm_settings::{PwmSetting, PWM_DEFAULT};

use once_cell::sync::Lazy;
use std::{rc::Rc, sync::Mutex, vec::Vec};
use strum::VariantNames;

use slint::{ModelRc, SharedString, VecModel};

use passwordmaker_rs::{
    HashAlgorithm, LeetLevel, ProtocolUsageMode, UrlParsing, UseLeetWhenGenerating,
};

// Model data has static life time, must exist as long as the app, accessible from callbacks
static PWM_DATA: Lazy<Mutex<PwmGuiData>> = Lazy::new(|| {
    Mutex::new({
        let pgdata = PwmGuiData::new();
        pgdata
    })
});

// rust slint type conversion
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

// Callbacks
fn on_url_edited(url: SharedString) -> SharedString {
    let pwm = match PWM_DATA.lock() {
        Ok(pwm) => pwm,
        Err(_) => return SharedString::from("No Lock!"),
    };
    let use_protocol = if pwm.get_current_setting_data().use_protocol {
        ProtocolUsageMode::Used
    } else {
        ProtocolUsageMode::Ignored
    };
    let urlparse = UrlParsing::new(
        use_protocol,
        pwm.get_current_setting_data().use_userinfo,
        pwm.get_current_setting_data().use_subdomain,
        pwm.get_current_setting_data().use_domain,
        pwm.get_current_setting_data().use_params,
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
        Ok(pwm) => match pwm.get_current_setting().try_into() {
            Ok(cs) => cs,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

fn on_set_current_setting(current_setting: i32) {
    match PWM_DATA.lock() {
        Ok(mut pwm) => match current_setting.try_into() {
            Ok(cs) => pwm.set_current_setting(cs),
            Err(_) => pwm.set_current_setting(0),
        },
        Err(_) => (),
    }
}

fn on_get_available_settings() -> ModelRc<SharedString> {
    let setting_names = match PWM_DATA.lock() {
        Ok(pwm) => pwm.get_setting_names(),
        Err(_) => Vec::<SharedString>::new(),
    };
    let vm_setting_names = VecModel::from(setting_names);
    ModelRc::from(Rc::new(vm_setting_names))
}

fn on_model_add_setting() {
    match PWM_DATA.lock() {
        Err(_) => return,
        Ok(mut pwm) => {
            pwm.add_setting();
        }
    }
}

fn on_model_delete_setting() {
    match PWM_DATA.lock() {
        Err(_) => return,
        Ok(mut pwm) => {
            pwm.delete_setting();
        }
    }
}

fn on_get_setting_data() -> PwmSlintSetting {
    match PWM_DATA.lock() {
        Ok(pwm) => pwm.get_current_setting_data().clone().into(),
        Err(_) => PWM_DEFAULT.clone().into(),
    }
}

fn on_set_setting_data(setting: PwmSlintSetting) {
    match PWM_DATA.lock() {
        Ok(mut pwm) => pwm.set_current_setting_data(setting.into()),
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
