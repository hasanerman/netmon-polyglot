#![allow(clippy::missing_safety_doc)]

mod analytics;
mod core;
mod sniffer;
mod types;

use std::ffi::{c_char, CStr};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::{ptr, slice};

use netcore_engine::pcap::PcapWriter;
use netcore_engine::synth::{self, Scenario};
use netcore_engine::LinkType;

const DEMO_SNAPLEN: u32 = 65_535;

pub use crate::core::NcCore;
pub use crate::types::*;

fn guarded(core: *const NcCore, f: impl FnOnce(&NcCore) -> Result<i32, CoreError>) -> i32 {
    let Some(core) = (unsafe { core.as_ref() }) else {
        return NcStatus::NullArg as i32;
    };
    match catch_unwind(AssertUnwindSafe(|| f(core))) {
        Ok(Ok(value)) => value,
        Ok(Err(e)) => {
            core.set_error(&e.message);
            e.status as i32
        }
        Err(_) => {
            core.set_error("internal panic in netcore");
            NcStatus::Panic as i32
        }
    }
}

fn ok() -> Result<i32, CoreError> {
    Ok(NcStatus::Ok as i32)
}

unsafe fn utf8_arg<'a>(p: *const c_char, what: &str) -> Result<&'a str, CoreError> {
    if p.is_null() {
        return Err(CoreError::new(NcStatus::NullArg, format!("{what} is null")));
    }
    CStr::from_ptr(p)
        .to_str()
        .map_err(|_| CoreError::new(NcStatus::InvalidArg, format!("{what} is not valid utf-8")))
}

fn null_arg(what: &str) -> CoreError {
    CoreError::new(NcStatus::NullArg, format!("{what} is null"))
}

#[no_mangle]
pub extern "C" fn core_abi_version() -> u32 {
    NC_ABI_VERSION
}

#[no_mangle]
pub unsafe extern "C" fn core_create(config: *const NcConfig) -> *mut NcCore {
    let cfg = config.as_ref().copied().unwrap_or_default();
    match catch_unwind(|| NcCore::new(&cfg)) {
        Ok(Ok(core)) => Box::into_raw(Box::new(core)),
        _ => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn core_destroy(core: *mut NcCore) {
    if !core.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(core))));
    }
}

#[no_mangle]
pub unsafe extern "C" fn core_feed_packet(
    core: *mut NcCore,
    ts_us: u64,
    data: *const u8,
    caplen: u32,
    wire_len: u32,
) -> i32 {
    guarded(core, |c| {
        let bytes = match (data.is_null(), caplen) {
            (_, 0) => &[][..],
            (true, _) => return Err(null_arg("data")),
            (false, n) => slice::from_raw_parts(data, n as usize),
        };
        c.feed(ts_us, bytes, wire_len.max(caplen));
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_open_live(core: *mut NcCore, iface: *const c_char, promisc: u8) -> i32 {
    guarded(core, |c| {
        c.open_live(utf8_arg(iface, "iface")?, promisc != 0)?;
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_open_file(core: *mut NcCore, path: *const c_char, realtime: u8) -> i32 {
    guarded(core, |c| {
        c.open_file(utf8_arg(path, "path")?, realtime != 0)?;
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_load_rules(core: *mut NcCore, path: *const c_char) -> i32 {
    guarded(core, |c| {
        let active = c.load_rules(utf8_arg(path, "path")?)?;
        Ok(i32::try_from(active).unwrap_or(i32::MAX))
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_connect_analytics(core: *mut NcCore, endpoint: *const c_char) -> i32 {
    guarded(core, |c| {
        c.connect_analytics(utf8_arg(endpoint, "endpoint")?)?;
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_disconnect_analytics(core: *mut NcCore) -> i32 {
    guarded(core, |c| {
        c.disconnect_analytics();
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_start(core: *mut NcCore) -> i32 {
    guarded(core, |c| {
        c.start()?;
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_stop(core: *mut NcCore) -> i32 {
    guarded(core, |c| {
        c.stop()?;
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_poll_stats(core: *mut NcCore, out: *mut NcStats) -> i32 {
    guarded(core, |c| {
        let out = out.as_mut().ok_or_else(|| null_arg("out"))?;
        *out = c.stats();
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_poll_top_flows(
    core: *mut NcCore,
    out: *mut NcFlow,
    capacity: u32,
    written: *mut u32,
) -> i32 {
    guarded(core, |c| {
        let written = written.as_mut().ok_or_else(|| null_arg("written"))?;
        *written = 0;
        if capacity == 0 {
            return ok();
        }
        if out.is_null() {
            return Err(null_arg("out"));
        }
        let slots = slice::from_raw_parts_mut(out, capacity as usize);
        *written = c.top_flows(slots) as u32;
        ok()
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_poll_alert(core: *mut NcCore, out: *mut NcAlert) -> i32 {
    guarded(core, |c| {
        let out = out.as_mut().ok_or_else(|| null_arg("out"))?;
        match c.pop_alert() {
            Some(alert) => {
                *out = NcAlert::new(&alert);
                Ok(1)
            }
            None => Ok(0),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn core_last_error(core: *const NcCore, buf: *mut c_char, len: u32) -> i32 {
    guarded(core, |c| {
        if buf.is_null() || len == 0 {
            return Err(null_arg("buf"));
        }
        let dst = slice::from_raw_parts_mut(buf.cast::<u8>(), len as usize);
        write_cstr(dst, &c.last_error());
        ok()
    })
}

fn plain_status(result: std::thread::Result<Result<(), NcStatus>>) -> i32 {
    match result {
        Ok(Ok(())) => NcStatus::Ok as i32,
        Ok(Err(status)) => status as i32,
        Err(_) => NcStatus::Panic as i32,
    }
}

#[no_mangle]
pub unsafe extern "C" fn core_write_demo_pcap(path: *const c_char, scenario: u32, packets: u32, seed: u64) -> i32 {
    plain_status(catch_unwind(AssertUnwindSafe(|| -> Result<(), NcStatus> {
        let path = utf8_arg(path, "path").map_err(|e| e.status)?;
        let scenario = match scenario {
            s if s == NcScenario::Mixed as u32 => Scenario::Mixed,
            s if s == NcScenario::PortScan as u32 => Scenario::PortScan,
            s if s == NcScenario::DnsTunnel as u32 => Scenario::DnsTunnel,
            _ => return Err(NcStatus::InvalidArg),
        };
        let io = |_| NcStatus::Io;
        let file = File::create(path).map_err(io)?;
        let mut writer = PcapWriter::new(BufWriter::new(file), LinkType::Ethernet, DEMO_SNAPLEN).map_err(io)?;
        synth::generate(scenario, packets as usize, seed, |ts, frame| writer.write_record(ts, frame)).map_err(io)?;
        writer.into_inner().flush().map_err(io)
    })))
}

#[no_mangle]
pub unsafe extern "C" fn core_list_devices(out: *mut NcDevice, capacity: u32, total: *mut u32) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), NcStatus> {
        let total = total.as_mut().ok_or(NcStatus::NullArg)?;
        let devices = sniffer::list_devices().map_err(|e| e.status)?;
        *total = devices.len() as u32;
        if capacity > 0 {
            if out.is_null() {
                return Err(NcStatus::NullArg);
            }
            let slots = slice::from_raw_parts_mut(out, capacity as usize);
            for (slot, d) in slots.iter_mut().zip(&devices) {
                *slot = NcDevice::new(&d.name, &d.description, d.flags);
            }
        }
        Ok(())
    }));
    plain_status(result)
}

#[no_mangle]
pub extern "C" fn core_status_str(status: i32) -> *const c_char {
    let text: &'static CStr = match status {
        0 => c"ok",
        -1 => c"null argument",
        -2 => c"invalid argument",
        -3 => c"invalid state",
        -4 => c"i/o error",
        -5 => c"capture error",
        -6 => c"capture library (npcap/libpcap) not installed",
        -7 => c"permission denied",
        -8 => c"internal panic",
        -9 => c"rules error",
        -10 => c"bad file format",
        _ => c"unknown status",
    };
    text.as_ptr()
}
