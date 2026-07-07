use libc::{c_char, c_int, c_uint, c_void};
use std::{
    ffi::{CStr, CString},
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

const SUDO_APPROVAL_PLUGIN: c_uint = 4;
const SUDO_API_VERSION: c_uint = (1 << 16) | 21;
const SUDO_CONV_INFO_MSG: c_int = 0x0004;

type SudoConv = *mut c_void;
type SudoPrintf = unsafe extern "C" fn(c_int, *const c_char, ...) -> c_int;

#[repr(C)]
pub struct ApprovalPlugin {
    type_: c_uint,
    version: c_uint,
    open: Option<
        unsafe extern "C" fn(
            c_uint,
            SudoConv,
            Option<SudoPrintf>,
            *mut *mut c_char,
            *mut *mut c_char,
            c_int,
            *mut *mut c_char,
            *mut *mut c_char,
            *mut *mut c_char,
            *mut *const c_char,
        ) -> c_int,
    >,
    close: Option<unsafe extern "C" fn()>,
    check: Option<
        unsafe extern "C" fn(
            *mut *mut c_char,
            *mut *mut c_char,
            *mut *mut c_char,
            *mut *const c_char,
        ) -> c_int,
    >,
    show_version: Option<unsafe extern "C" fn(c_int) -> c_int>,
}

struct OpenCtx {
    uid: u32,
    cwd: String,
    runas: String,
    socket_path: String,
}

static OPEN_CTX: OnceLock<Mutex<Option<OpenCtx>>> = OnceLock::new();
static PRINTF: OnceLock<Mutex<Option<SudoPrintf>>> = OnceLock::new();

#[no_mangle]
pub static judo_approval: ApprovalPlugin = ApprovalPlugin {
    type_: SUDO_APPROVAL_PLUGIN,
    version: SUDO_API_VERSION,
    open: Some(open),
    close: Some(close),
    check: Some(check),
    show_version: Some(show_version),
};

unsafe extern "C" fn open(
    _version: c_uint,
    _conversation: SudoConv,
    plugin_printf: Option<SudoPrintf>,
    _settings: *mut *mut c_char,
    user_info: *mut *mut c_char,
    _submit_optind: c_int,
    _submit_argv: *mut *mut c_char,
    _submit_envp: *mut *mut c_char,
    plugin_options: *mut *mut c_char,
    _errstr: *mut *const c_char,
) -> c_int {
    *PRINTF.get_or_init(|| Mutex::new(None)).lock().unwrap() = plugin_printf;
    let user_info = collect_array(user_info);
    let plugin_options = collect_array(plugin_options);
    let uid = value(&user_info, "uid=")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(|| libc::getuid() as u32);
    let cwd = value(&user_info, "cwd=").unwrap_or_else(|| "/".to_string());
    let runas = value(&user_info, "runas_user=").unwrap_or_else(|| "root".to_string());
    let socket_path = plugin_options
        .iter()
        .find_map(|s| s.strip_prefix("SocketPath=").map(ToOwned::to_owned))
        .unwrap_or_else(default_socket_path);

    *OPEN_CTX.get_or_init(|| Mutex::new(None)).lock().unwrap() = Some(OpenCtx {
        uid,
        cwd,
        runas,
        socket_path,
    });
    1
}

unsafe extern "C" fn close() {
    *OPEN_CTX.get_or_init(|| Mutex::new(None)).lock().unwrap() = None;
}

unsafe extern "C" fn check(
    command_info: *mut *mut c_char,
    run_argv: *mut *mut c_char,
    _run_envp: *mut *mut c_char,
    errstr: *mut *const c_char,
) -> c_int {
    let command_info = collect_array(command_info);
    let argv = collect_array(run_argv);
    let ctx = match OPEN_CTX
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .as_ref()
    {
        Some(ctx) => OpenCtx {
            uid: ctx.uid,
            cwd: ctx.cwd.clone(),
            runas: value(&command_info, "runas_user=").unwrap_or_else(|| ctx.runas.clone()),
            socket_path: ctx.socket_path.clone(),
        },
        None => {
            set_err(errstr, "judo plugin was not opened");
            return 0;
        }
    };

    match ask_daemon(&ctx, argv) {
        Ok((allow, message)) => {
            print_msg(&message);
            if allow {
                1
            } else {
                0
            }
        }
        Err(err) => {
            let message = format!("judo approval failed: {err}");
            print_msg(&message);
            set_err(errstr, &message);
            0
        }
    }
}

unsafe extern "C" fn show_version(_verbose: c_int) -> c_int {
    print_msg("judo approval plugin 0.1.0");
    1
}

fn ask_daemon(ctx: &OpenCtx, argv: Vec<String>) -> Result<(bool, String), String> {
    let mut stream = UnixStream::connect(&ctx.socket_path)
        .map_err(|e| format!("connect {}: {e}", ctx.socket_path))?;
    let req = judo_proto::LocalReq::Request {
        uid: ctx.uid,
        cwd: ctx.cwd.clone(),
        runas: ctx.runas.clone(),
        argv,
    };
    let req = serde_json::to_string(&req).map_err(|e| e.to_string())?;
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(b"\n").map_err(|e| e.to_string())?;

    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let resp: judo_proto::LocalResp =
        serde_json::from_str(line.trim()).map_err(|e| e.to_string())?;
    match resp {
        judo_proto::LocalResp::Verdict { verdict, message } => Ok((verdict == "allow", message)),
        judo_proto::LocalResp::Err { message } => Err(message),
        other => Err(format!("unexpected daemon response: {other:?}")),
    }
}

unsafe fn collect_array(mut ptr: *mut *mut c_char) -> Vec<String> {
    let mut out = Vec::new();
    if ptr.is_null() {
        return out;
    }
    while !(*ptr).is_null() {
        out.push(CStr::from_ptr(*ptr).to_string_lossy().into_owned());
        ptr = ptr.add(1);
    }
    out
}

fn value(items: &[String], prefix: &str) -> Option<String> {
    items
        .iter()
        .find_map(|item| item.strip_prefix(prefix).map(ToOwned::to_owned))
}

fn default_socket_path() -> String {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(xdg)
            .join("judo")
            .join("judo.sock")
            .to_string_lossy()
            .to_string();
    }
    let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
    PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("judo")
        .join("judo.sock")
        .to_string_lossy()
        .to_string()
}

fn print_msg(message: &str) {
    let Some(lock) = PRINTF.get() else {
        eprintln!("{message}");
        return;
    };
    let Some(printf) = *lock.lock().unwrap() else {
        eprintln!("{message}");
        return;
    };
    let Ok(fmt) = CString::new("%s\n") else {
        return;
    };
    let Ok(msg) = CString::new(message) else {
        return;
    };
    unsafe {
        printf(SUDO_CONV_INFO_MSG, fmt.as_ptr(), msg.as_ptr());
    }
}

fn set_err(errstr: *mut *const c_char, message: &str) {
    if errstr.is_null() {
        return;
    }
    if let Ok(c) = CString::new(message) {
        unsafe {
            *errstr = c.into_raw();
        }
    }
}
