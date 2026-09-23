use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr::{self, NonNull};

use crate::types::{CoreError, NcStatus};

const ERRBUF_LEN: usize = 256;
const NAME_LEN: usize = 256;

mod sys {
    use super::*;

    #[repr(C)]
    pub struct Opaque {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub struct Frame {
        pub ts_us: u64,
        pub caplen: u32,
        pub len: u32,
        pub data: *const u8,
    }

    #[repr(C)]
    pub struct Device {
        pub name: [c_char; NAME_LEN],
        pub description: [c_char; NAME_LEN],
        pub flags: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct Stats {
        pub delivered: u64,
        pub received: u32,
        pub dropped: u32,
        pub if_dropped: u32,
    }

    pub type Callback = unsafe extern "C" fn(frame: *const Frame, user: *mut c_void);

    extern "C" {
        pub fn sniffer_list_devices(
            out: *mut Device,
            capacity: usize,
            total: *mut usize,
            errbuf: *mut c_char,
            errlen: usize,
        ) -> c_int;
        pub fn sniffer_open_live(
            out: *mut *mut Opaque,
            iface: *const c_char,
            snaplen: c_int,
            promisc: c_int,
            errbuf: *mut c_char,
            errlen: usize,
        ) -> c_int;
        pub fn sniffer_open_file(
            out: *mut *mut Opaque,
            path: *const c_char,
            errbuf: *mut c_char,
            errlen: usize,
        ) -> c_int;
        pub fn sniffer_set_callback(s: *mut Opaque, cb: Callback, user: *mut c_void) -> c_int;
        pub fn sniffer_set_realtime(s: *mut Opaque, enabled: c_int) -> c_int;
        pub fn sniffer_start(s: *mut Opaque) -> c_int;
        pub fn sniffer_stop(s: *mut Opaque) -> c_int;
        pub fn sniffer_poll_finished(s: *mut Opaque, status: *mut c_int) -> c_int;
        pub fn sniffer_link_type(s: *const Opaque) -> c_int;
        pub fn sniffer_get_stats(s: *mut Opaque, out: *mut Stats) -> c_int;
        pub fn sniffer_last_error(s: *const Opaque) -> *const c_char;
        pub fn sniffer_close(s: *mut Opaque);
    }
}

pub use sys::{Callback, Frame};

pub struct DeviceInfo {
    pub name: String,
    pub description: String,
    pub flags: u32,
}

pub struct CaptureStats {
    pub dropped: u64,
}

pub struct Sniffer {
    raw: NonNull<sys::Opaque>,
    running: bool,
}

// sniffer handle'i tek sahipli, mutex arkasinda tasiniyor
unsafe impl Send for Sniffer {}

fn map_status(code: c_int) -> NcStatus {
    match code {
        -1 => NcStatus::InvalidArg,
        -2 => NcStatus::NoLibrary,
        -4 => NcStatus::Permission,
        -5 => NcStatus::State,
        -7 => NcStatus::Io,
        -8 => NcStatus::Format,
        _ => NcStatus::Capture,
    }
}

fn errbuf_message(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn c_string(value: &str, what: &str) -> Result<CString, CoreError> {
    CString::new(value).map_err(|_| CoreError::new(NcStatus::InvalidArg, format!("{what} contains a NUL byte")))
}

fn opened(code: c_int, raw: *mut sys::Opaque, errbuf: &[c_char]) -> Result<Sniffer, CoreError> {
    match NonNull::new(raw) {
        Some(raw) if code == 0 => Ok(Sniffer { raw, running: false }),
        _ => Err(CoreError::new(map_status(code), errbuf_message(errbuf))),
    }
}

impl Sniffer {
    pub fn open_live(iface: &str, snaplen: u32, promisc: bool) -> Result<Self, CoreError> {
        let iface = c_string(iface, "interface name")?;
        let snaplen = c_int::try_from(snaplen).map_err(|_| CoreError::new(NcStatus::InvalidArg, "snaplen too large"))?;
        let mut raw = ptr::null_mut();
        let mut err = [0 as c_char; ERRBUF_LEN];
        let code = unsafe {
            sys::sniffer_open_live(&mut raw, iface.as_ptr(), snaplen, c_int::from(promisc), err.as_mut_ptr(), err.len())
        };
        opened(code, raw, &err)
    }

    pub fn open_file(path: &str) -> Result<Self, CoreError> {
        let path = c_string(path, "path")?;
        let mut raw = ptr::null_mut();
        let mut err = [0 as c_char; ERRBUF_LEN];
        let code = unsafe { sys::sniffer_open_file(&mut raw, path.as_ptr(), err.as_mut_ptr(), err.len()) };
        opened(code, raw, &err)
    }

    /// # Safety
    /// `user` must stay valid until the sniffer is stopped or dropped.
    pub unsafe fn set_callback(&mut self, cb: Callback, user: *mut c_void) -> Result<(), CoreError> {
        let code = sys::sniffer_set_callback(self.raw.as_ptr(), cb, user);
        self.check(code)
    }

    pub fn set_realtime(&mut self, enabled: bool) -> Result<(), CoreError> {
        let code = unsafe { sys::sniffer_set_realtime(self.raw.as_ptr(), c_int::from(enabled)) };
        self.check(code)
    }

    pub fn start(&mut self) -> Result<(), CoreError> {
        let code = unsafe { sys::sniffer_start(self.raw.as_ptr()) };
        self.check(code)?;
        self.running = true;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), CoreError> {
        let code = unsafe { sys::sniffer_stop(self.raw.as_ptr()) };
        self.running = false;
        self.check(code)
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn finished(&mut self) -> Option<Result<(), CoreError>> {
        let mut status: c_int = 0;
        let done = unsafe { sys::sniffer_poll_finished(self.raw.as_ptr(), &mut status) };
        (done == 1).then(|| self.check(status))
    }

    pub fn link_type(&self) -> i32 {
        unsafe { sys::sniffer_link_type(self.raw.as_ptr()) }
    }

    pub fn stats(&mut self) -> Result<CaptureStats, CoreError> {
        let mut st = sys::Stats::default();
        let code = unsafe { sys::sniffer_get_stats(self.raw.as_ptr(), &mut st) };
        self.check(code)?;
        Ok(CaptureStats {
            dropped: u64::from(st.dropped) + u64::from(st.if_dropped),
        })
    }

    fn check(&self, code: c_int) -> Result<(), CoreError> {
        if code == 0 {
            return Ok(());
        }
        let msg = unsafe { CStr::from_ptr(sys::sniffer_last_error(self.raw.as_ptr())) };
        Err(CoreError::new(map_status(code), msg.to_string_lossy().into_owned()))
    }
}

impl Drop for Sniffer {
    fn drop(&mut self) {
        unsafe { sys::sniffer_close(self.raw.as_ptr()) };
    }
}

pub fn list_devices() -> Result<Vec<DeviceInfo>, CoreError> {
    let mut err = [0 as c_char; ERRBUF_LEN];
    let mut total = 0usize;
    let code = unsafe { sys::sniffer_list_devices(ptr::null_mut(), 0, &mut total, err.as_mut_ptr(), err.len()) };
    if code != 0 {
        return Err(CoreError::new(map_status(code), errbuf_message(&err)));
    }

    let mut devices: Vec<sys::Device> = (0..total)
        .map(|_| sys::Device {
            name: [0; NAME_LEN],
            description: [0; NAME_LEN],
            flags: 0,
        })
        .collect();
    let code = unsafe {
        sys::sniffer_list_devices(devices.as_mut_ptr(), devices.len(), &mut total, err.as_mut_ptr(), err.len())
    };
    if code != 0 {
        return Err(CoreError::new(map_status(code), errbuf_message(&err)));
    }
    devices.truncate(total);
    Ok(devices
        .iter()
        .map(|d| DeviceInfo {
            name: errbuf_message(&d.name),
            description: errbuf_message(&d.description),
            flags: d.flags,
        })
        .collect())
}
