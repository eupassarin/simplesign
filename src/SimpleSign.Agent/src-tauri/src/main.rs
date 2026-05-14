#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Certificate {
    thumbprint: String,
    subject: String,
    issuer: String,
    #[serde(rename = "validFrom")]
    valid_from: String,
    #[serde(rename = "validTo")]
    valid_to: String,
}

#[cfg(target_os = "windows")]
fn enumerate_certificates() -> Vec<Certificate> {
    use windows::Win32::Security::Cryptography::*;
    use windows::core::*;

    let mut certs = Vec::new();

    unsafe {
        let store_name = w!("MY");
        let store = match CertOpenSystemStoreW(None, store_name) {
            Ok(h) => h,
            Err(_) => return certs,
        };

        let mut prev: *mut CERT_CONTEXT = std::ptr::null_mut();
        loop {
            let cert_ctx = CertEnumCertificatesInStore(
                store,
                if prev.is_null() { None } else { Some(prev) },
            );
            if cert_ctx.is_null() {
                break;
            }

            let subject = get_cert_name(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
            let issuer =
                get_cert_name(cert_ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);

            let info = &*(*cert_ctx).pCertInfo;
            let valid_from = filetime_to_string(&info.NotBefore);
            let valid_to = filetime_to_string(&info.NotAfter);

            // Skip expired certificates
            if is_cert_expired(&info.NotAfter) {
                prev = cert_ctx;
                continue;
            }

            // Skip self-signed certificates (subject == issuer)
            if subject == issuer {
                prev = cert_ctx;
                continue;
            }

            let cert_data = std::slice::from_raw_parts(
                (*cert_ctx).pbCertEncoded,
                (*cert_ctx).cbCertEncoded as usize,
            );
            let thumbprint = sha1_hex(cert_data);

            // Check if certificate has a private key via property query
            let has_key = CertGetCertificateContextProperty(
                cert_ctx,
                CERT_KEY_PROV_INFO_PROP_ID,
                None,
                &mut 0u32,
            ).is_ok();

            if has_key {
                certs.push(Certificate {
                    thumbprint,
                    subject,
                    issuer,
                    valid_from,
                    valid_to,
                });
            }

            prev = cert_ctx;
        }

        let _ = CertCloseStore(Some(store), 0);
    }

    certs
}

#[cfg(target_os = "windows")]
fn is_cert_expired(not_after: &windows::Win32::Foundation::FILETIME) -> bool {
    // Convert FILETIME to unix timestamp and compare with current time
    let cert_ticks = ((not_after.dwHighDateTime as u64) << 32) | not_after.dwLowDateTime as u64;
    let cert_unix_secs = (cert_ticks / 10_000_000).saturating_sub(11_644_473_600);

    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    now_unix_secs > cert_unix_secs
}

#[cfg(target_os = "windows")]
unsafe fn get_cert_name(
    ctx: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    name_type: u32,
    flags: u32,
) -> String {
    use windows::Win32::Security::Cryptography::*;

    let len = CertGetNameStringW(ctx, name_type, flags, None, None);
    if len <= 1 {
        return String::from("Unknown");
    }
    let mut buf = vec![0u16; len as usize];
    CertGetNameStringW(ctx, name_type, flags, None, Some(&mut buf));
    if let Some(pos) = buf.iter().position(|&c| c == 0) {
        buf.truncate(pos);
    }
    String::from_utf16_lossy(&buf)
}

#[cfg(target_os = "windows")]
fn filetime_to_string(ft: &windows::Win32::Foundation::FILETIME) -> String {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    if ticks == 0 {
        return String::from("?");
    }
    let unix_secs = (ticks / 10_000_000).saturating_sub(11_644_473_600);
    let days = unix_secs / 86400;
    let (year, month, day) = days_to_ymd(days as i64);
    format!("{:04}-{:02}-{:02}", year, month, day)
}

#[cfg(target_os = "windows")]
fn days_to_ymd(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d)
}

#[cfg(target_os = "windows")]
fn sha1_hex(data: &[u8]) -> String {
    use windows::Win32::Security::Cryptography::*;

    unsafe {
        let mut hash = [0u8; 20];
        let mut size = 20u32;
        let _ = CryptHashCertificate(
            None,
            ALG_ID(CALG_SHA1.0),
            0,
            data,
            Some(hash.as_mut_ptr()),
            &mut size,
        );
        let mut hex = String::with_capacity(40);
        for b in &hash[..size as usize] {
            hex.push_str(&format!("{:02X}", b));
        }
        hex
    }
}

#[cfg(not(target_os = "windows"))]
fn enumerate_certificates() -> Vec<Certificate> {
    vec![]
}

#[tauri::command]
fn get_certificates() -> Vec<Certificate> {
    enumerate_certificates()
}

#[tauri::command]
fn sign_document(thumbprint: String) -> Result<String, String> {
    // TODO: Invoke SimpleSign CLI to perform signing
    println!("Signing with certificate: {}", thumbprint);
    Ok("signed".to_string())
}

/// Exports the DER-encoded public certificate for the given thumbprint.
#[tauri::command]
fn export_certificate(thumbprint: String) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        export_certificate_windows(&thumbprint)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = &thumbprint;
        Err("Certificate export is only supported on Windows".to_string())
    }
}

#[cfg(target_os = "windows")]
fn export_certificate_windows(thumbprint: &str) -> Result<String, String> {
    use windows::Win32::Security::Cryptography::*;
    use windows::core::*;

    let thumb_bytes = hex_decode(thumbprint)
        .map_err(|e| format!("Invalid thumbprint: {}", e))?;

    unsafe {
        let store = CertOpenSystemStoreW(None, w!("MY"))
            .map_err(|e| format!("Cannot open certificate store: {}", e))?;

        let hash_blob = CRYPT_INTEGER_BLOB {
            cbData: thumb_bytes.len() as u32,
            pbData: thumb_bytes.as_ptr() as *mut u8,
        };

        let cert_ctx = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            Some(&hash_blob as *const _ as *const _),
            None,
        );

        if cert_ctx.is_null() {
            let _ = CertCloseStore(Some(store), 0);
            return Err("Certificate not found in store".to_string());
        }

        let cert_data = std::slice::from_raw_parts(
            (*cert_ctx).pbCertEncoded,
            (*cert_ctx).cbCertEncoded as usize,
        );

        let result = base64_encode(cert_data);
        let _ = CertCloseStore(Some(store), 0);
        Ok(result)
    }
}

#[cfg(target_os = "windows")]
fn get_tauri_window_hwnd(window: &tauri::Window) -> usize {
    match window.hwnd() {
        Ok(hwnd) => hwnd.0 as usize,
        Err(_) => 0,
    }
}

/// Signs a hash using the private key of the certificate identified by thumbprint.
/// This enables A3 (smart card/token) signing: the CLI prepares the PDF and computes
/// the hash, then sends it here for signing with the hardware-bound private key.
#[tauri::command]
fn sign_hash(thumbprint: String, hash_base64: String, algorithm: String) -> Result<String, String> {
    sign_hash_with_hwnd(thumbprint, hash_base64, algorithm, 0)
}

fn sign_hash_with_hwnd(thumbprint: String, hash_base64: String, algorithm: String, hwnd: usize) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        sign_hash_windows(&thumbprint, &hash_base64, &algorithm, hwnd)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (&thumbprint, &hash_base64, &algorithm, hwnd);
        Err("Signing is only supported on Windows".to_string())
    }
}

#[cfg(target_os = "windows")]
fn sign_hash_windows(thumbprint: &str, hash_base64: &str, algorithm: &str, parent_hwnd: usize) -> Result<String, String> {
    use windows::Win32::Security::Cryptography::*;
    use windows::core::*;

    // Decode the hash from base64
    let hash_bytes = base64_decode(hash_base64)
        .map_err(|e| format!("Invalid base64: {}", e))?;

    // Decode thumbprint from hex
    let thumb_bytes = hex_decode(thumbprint)
        .map_err(|e| format!("Invalid thumbprint: {}", e))?;

    unsafe {
        let store = CertOpenSystemStoreW(None, w!("MY"))
            .map_err(|e| format!("Cannot open certificate store: {}", e))?;

        // Find certificate by thumbprint
        let hash_blob = CRYPT_INTEGER_BLOB {
            cbData: thumb_bytes.len() as u32,
            pbData: thumb_bytes.as_ptr() as *mut u8,
        };

        let cert_ctx = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_HASH,
            Some(&hash_blob as *const _ as *const _),
            None,
        );

        if cert_ctx.is_null() {
            let _ = CertCloseStore(Some(store), 0);
            return Err("Certificate not found in store".to_string());
        }

        // Acquire the private key - try CAPI first (most Brazilian tokens are CAPI-based)
        let mut key_handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE(0);
        let mut key_spec = CERT_KEY_SPEC(0);
        let mut must_free = windows::core::BOOL(0);

        // First try without NCRYPT flag to get pure CAPI handle
        let acquired = CryptAcquireCertificatePrivateKey(
            cert_ctx,
            CRYPT_ACQUIRE_FLAGS(0),
            None,
            &mut key_handle as *mut _,
            Some(&mut key_spec as *mut _),
            Some(&mut must_free as *mut _),
        );

        if acquired.is_err() {
            // Fallback to NCRYPT
            let acquired2 = CryptAcquireCertificatePrivateKey(
                cert_ctx,
                CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
                None,
                &mut key_handle as *mut _,
                Some(&mut key_spec as *mut _),
                Some(&mut must_free as *mut _),
            );
            if acquired2.is_err() {
                let _ = CertCloseStore(Some(store), 0);
                return Err("Cannot acquire private key (is the smart card inserted?)".to_string());
            }
        }

        let hwnd = if parent_hwnd != 0 { parent_hwnd } else { get_foreground_window() };

        let result = if key_spec == CERT_NCRYPT_KEY_SPEC {
            // CNG path - set the window handle so PIN dialog can appear
            if hwnd != 0 {
                let _ = NCryptSetProperty(
                    NCRYPT_KEY_HANDLE(key_handle.0).into(),
                    w!("HWND Handle"),
                    &hwnd.to_ne_bytes(),
                    NCRYPT_FLAGS(0),
                );
            }
            sign_with_ncrypt(key_handle.0, &hash_bytes, algorithm)
        } else {
            // CAPI path - set window handle for PIN dialog, then sign
            sign_with_capi_ffi(key_handle.0, key_spec.0, &hash_bytes, algorithm, hwnd)
        };

        if must_free.as_bool() {
            if key_spec == CERT_NCRYPT_KEY_SPEC {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(key_handle.0));
            }
            // CAPI handles are released by sign_with_capi_ffi or left for Windows to clean up
        }

        let _ = CertCloseStore(Some(store), 0);
        result
    }
}

#[cfg(target_os = "windows")]
fn get_foreground_window() -> usize {
    #[link(name = "user32")]
    extern "system" {
        fn GetForegroundWindow() -> usize;
    }
    unsafe { GetForegroundWindow() }
}

/// CAPI-based signing using raw FFI - for hardware tokens that don't support CNG
#[cfg(target_os = "windows")]
unsafe fn sign_with_capi_ffi(
    hprov: usize,
    key_spec: u32,
    hash: &[u8],
    algorithm: &str,
    hwnd: usize,
) -> Result<String, String> {
    #[link(name = "advapi32")]
    extern "system" {
        fn CryptSetProvParam(hprov: usize, param: u32, data: *const u8, flags: u32) -> i32;
        fn CryptCreateHash(hprov: usize, algid: u32, hkey: usize, flags: u32, phash: *mut usize) -> i32;
        fn CryptHashData(hhash: usize, data: *const u8, data_len: u32, flags: u32) -> i32;
        fn CryptSignHashW(hhash: usize, key_spec: u32, description: *const u16, flags: u32, sig: *mut u8, sig_len: *mut u32) -> i32;
        fn CryptDestroyHash(hhash: usize) -> i32;
    }

    const PP_CLIENT_HWND: u32 = 1;

    let calg: u32 = match algorithm.to_uppercase().as_str() {
        "SHA256" | "SHA-256" => 0x0000800c, // CALG_SHA_256
        "SHA384" | "SHA-384" => 0x0000800d, // CALG_SHA_384
        "SHA512" | "SHA-512" => 0x0000800e, // CALG_SHA_512
        _ => 0x0000800c,
    };

    // Set window handle for PIN dialog
    if hwnd != 0 {
        let hwnd_val = hwnd;
        CryptSetProvParam(hprov, PP_CLIENT_HWND, &hwnd_val as *const usize as *const u8, 0);
    }

    // Create hash object
    let mut hhash: usize = 0;
    if CryptCreateHash(hprov, calg, 0, 0, &mut hhash) == 0 {
        return Err(format!(
            "CryptCreateHash failed (alg=0x{:08x}): GetLastError={}",
            calg,
            std::io::Error::last_os_error()
        ));
    }

    // Hash the data (signed attributes) - NOT setting a pre-computed hash
    if CryptHashData(hhash, hash.as_ptr(), hash.len() as u32, 0) == 0 {
        let err = std::io::Error::last_os_error();
        CryptDestroyHash(hhash);
        return Err(format!("CryptHashData failed: {}", err));
    }

    // Get signature size
    let mut sig_len: u32 = 0;
    if CryptSignHashW(hhash, key_spec, std::ptr::null(), 0, std::ptr::null_mut(), &mut sig_len) == 0 {
        let err = std::io::Error::last_os_error();
        CryptDestroyHash(hhash);
        return Err(format!("CryptSignHash (size query) failed: {}", err));
    }

    // Sign
    let mut signature = vec![0u8; sig_len as usize];
    if CryptSignHashW(hhash, key_spec, std::ptr::null(), 0, signature.as_mut_ptr(), &mut sig_len) == 0 {
        let err = std::io::Error::last_os_error();
        CryptDestroyHash(hhash);
        return Err(format!("CryptSignHash failed: {}", err));
    }

    CryptDestroyHash(hhash);

    // CAPI returns signature in little-endian byte order; reverse for standard big-endian
    signature.truncate(sig_len as usize);
    signature.reverse();
    Ok(base64_encode(&signature))
}

#[cfg(target_os = "windows")]
unsafe fn sign_with_ncrypt(key_handle: usize, data: &[u8], algorithm: &str) -> Result<String, String> {
    use windows::Win32::Security::Cryptography::*;
    use windows::core::*;

    let ncrypt_key = NCRYPT_KEY_HANDLE(key_handle);

    // Hash the data (signed attributes) first - NCryptSignHash expects a digest
    let hash = compute_hash(data, algorithm);

    // Allocate 512 bytes - enough for RSA up to 4096-bit keys
    let sig_buf_size = 512usize;

    // Map algorithm name to BCRYPT padding info
    let hash_alg: PCWSTR = match algorithm.to_uppercase().as_str() {
        "SHA256" | "SHA-256" => BCRYPT_SHA256_ALGORITHM,
        "SHA384" | "SHA-384" => BCRYPT_SHA384_ALGORITHM,
        "SHA512" | "SHA-512" => BCRYPT_SHA512_ALGORITHM,
        _ => BCRYPT_SHA256_ALGORITHM,
    };

    let padding = BCRYPT_PKCS1_PADDING_INFO {
        pszAlgId: hash_alg,
    };

    // Sign directly with pre-allocated buffer (some hardware tokens don't support size query)
    let mut signature = vec![0u8; sig_buf_size];
    let mut sig_size: u32 = 0;
    let status = NCryptSignHash(
        ncrypt_key,
        Some(&padding as *const _ as *const _),
        &hash,
        Some(&mut signature),
        &mut sig_size,
        NCRYPT_PAD_PKCS1_FLAG,
    );

    if status.is_err() {
        // Fallback: try without padding info (some CSPs handle padding internally)
        let status2 = NCryptSignHash(
            ncrypt_key,
            None,
            &hash,
            Some(&mut signature),
            &mut sig_size,
            NCRYPT_FLAGS(0),
        );
        if status2.is_err() {
            return Err(format!(
                "NCryptSignHash failed: {:?} (also tried without padding: {:?})",
                status, status2
            ));
        }
    }

    signature.truncate(sig_size as usize);
    Ok(base64_encode(&signature))
}

/// Compute hash of data using the specified algorithm
fn compute_hash(data: &[u8], algorithm: &str) -> Vec<u8> {
    #[cfg(target_os = "windows")]
    {
        compute_hash_windows(data, algorithm)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (data, algorithm);
        vec![]
    }
}

#[cfg(target_os = "windows")]
fn compute_hash_windows(data: &[u8], algorithm: &str) -> Vec<u8> {
    #[link(name = "advapi32")]
    extern "system" {
        fn CryptAcquireContextW(phprov: *mut usize, container: *const u16, provider: *const u16, prov_type: u32, flags: u32) -> i32;
        fn CryptCreateHash(hprov: usize, algid: u32, hkey: usize, flags: u32, phash: *mut usize) -> i32;
        fn CryptHashData(hhash: usize, data: *const u8, data_len: u32, flags: u32) -> i32;
        fn CryptGetHashParam(hhash: usize, param: u32, data: *mut u8, data_len: *mut u32, flags: u32) -> i32;
        fn CryptDestroyHash(hhash: usize) -> i32;
        fn CryptReleaseContext(hprov: usize, flags: u32) -> i32;
    }

    const PROV_RSA_AES: u32 = 24;
    const CRYPT_VERIFYCONTEXT: u32 = 0xF0000000;
    const HP_HASHVAL: u32 = 0x0002;

    let calg: u32 = match algorithm.to_uppercase().as_str() {
        "SHA256" | "SHA-256" => 0x0000800c,
        "SHA384" | "SHA-384" => 0x0000800d,
        "SHA512" | "SHA-512" => 0x0000800e,
        _ => 0x0000800c,
    };

    let hash_size: usize = match algorithm.to_uppercase().as_str() {
        "SHA256" | "SHA-256" => 32,
        "SHA384" | "SHA-384" => 48,
        "SHA512" | "SHA-512" => 64,
        _ => 32,
    };

    unsafe {
        let mut hprov: usize = 0;
        if CryptAcquireContextW(&mut hprov, std::ptr::null(), std::ptr::null(), PROV_RSA_AES, CRYPT_VERIFYCONTEXT) == 0 {
            return vec![0u8; hash_size];
        }

        let mut hhash: usize = 0;
        if CryptCreateHash(hprov, calg, 0, 0, &mut hhash) == 0 {
            CryptReleaseContext(hprov, 0);
            return vec![0u8; hash_size];
        }

        if CryptHashData(hhash, data.as_ptr(), data.len() as u32, 0) == 0 {
            CryptDestroyHash(hhash);
            CryptReleaseContext(hprov, 0);
            return vec![0u8; hash_size];
        }

        let mut hash_buf = vec![0u8; hash_size];
        let mut buf_len = hash_size as u32;
        if CryptGetHashParam(hhash, HP_HASHVAL, hash_buf.as_mut_ptr(), &mut buf_len, 0) == 0 {
            CryptDestroyHash(hhash);
            CryptReleaseContext(hprov, 0);
            return vec![0u8; hash_size];
        }

        CryptDestroyHash(hhash);
        CryptReleaseContext(hprov, 0);
        hash_buf
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("Invalid base64 char: {}", c as char)),
        }
    }
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=' && b != b'\n' && b != b'\r').collect();
    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 { break; }
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        result.push((a << 2) | (b >> 4));
        if chunk.len() > 2 {
            let c = val(chunk[2])?;
            result.push((b << 4) | (c >> 2));
            if chunk.len() > 3 {
                let d = val(chunk[3])?;
                result.push((c << 6) | d);
            }
        }
    }
    Ok(result)
}

fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let s: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return Err("Odd-length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ─── HTTP Server for CLI/Web communication ───

use std::sync::{Arc, Mutex};
use std::collections::HashMap;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SignSessionRequest {
    #[serde(rename = "fileName")]
    file_name: String,
    #[serde(rename = "hashAlgorithm")]
    hash_algorithm: String,
    #[serde(rename = "dataBase64", default)]
    data_base64: String,
    /// Optional thumbprint for multi-doc signing (skip cert selection UI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    thumbprint: Option<String>,
}

/// Session states:
/// - "pending": waiting for user to select certificate in Agent UI
/// - "cert_selected": user selected cert, client should prepare and PUT data
/// - "data_ready": client sent data via PUT, Agent should sign
/// - "signing": Agent is actively signing
/// - "signed": signing complete, signature available
/// - "cancelled": user cancelled
/// - "error": signing failed
#[derive(serde::Serialize, Clone)]
struct SignSessionState {
    id: String,
    status: String,
    request: SignSessionRequest,
    #[serde(skip_serializing_if = "Option::is_none")]
    thumbprint: Option<String>,
    #[serde(rename = "signatureBase64", skip_serializing_if = "Option::is_none")]
    signature_base64: Option<String>,
    #[serde(rename = "certificateBase64", skip_serializing_if = "Option::is_none")]
    certificate_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip)]
    created_at: std::time::Instant,
}

type Sessions = Arc<Mutex<HashMap<String, SignSessionState>>>;

fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    let pid = std::process::id();
    format!("{:016x}{:08x}", nanos, pid)
}

fn start_http_server(sessions: Sessions) {
    let server_sessions = sessions.clone();
    std::thread::spawn(move || {
        let listener = match std::net::TcpListener::bind("127.0.0.1:21599") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("HTTP server failed to bind on 127.0.0.1:21599: {}", e);
                return;
            }
        };

        for stream in listener.incoming() {
            let stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let sessions = server_sessions.clone();
            std::thread::spawn(move || {
                handle_http_request(stream, sessions);
            });
        }
    });

    // Session cleanup thread (expire sessions older than 5 minutes)
    let cleanup_sessions = sessions.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let mut map = cleanup_sessions.lock().unwrap();
            map.retain(|_, s| s.created_at.elapsed().as_secs() < 300);
        }
    });
}

fn handle_http_request(mut stream: std::net::TcpStream, sessions: Sessions) {
    use std::io::{Read, Write};

    // Set read timeout to avoid blocking forever
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));

    // Read headers first
    let mut buf = Vec::with_capacity(65536);
    let mut tmp = [0u8; 4096];
    let mut header_end = None;

    loop {
        let n = match stream.read(&mut tmp) {
            Ok(n) if n > 0 => n,
            _ => break,
        };
        buf.extend_from_slice(&tmp[..n]);

        // Check if we have the full headers
        if let Some(pos) = find_header_end(&buf) {
            header_end = Some(pos);
            break;
        }
        if buf.len() > 65536 {
            return; // Too large
        }
    }

    let header_end = match header_end {
        Some(pos) => pos,
        None => return,
    };

    let headers_str = String::from_utf8_lossy(&buf[..header_end]).to_string();

    // Parse Content-Length and read remaining body if needed
    let content_length = headers_str
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    let body_start = header_end + 4; // Skip \r\n\r\n
    let body_received = buf.len() - body_start;

    // Read remaining body bytes if needed
    if body_received < content_length {
        let remaining = content_length - body_received;
        let mut body_buf = vec![0u8; remaining];
        let mut read_so_far = 0;
        while read_so_far < remaining {
            match stream.read(&mut body_buf[read_so_far..]) {
                Ok(0) => break,
                Ok(n) => read_so_far += n,
                Err(_) => break,
            }
        }
        buf.extend_from_slice(&body_buf[..read_so_far]);
    }

    let request = String::from_utf8_lossy(&buf).to_string();

    // Parse method and path from first line
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 { return; }
    let method = parts[0];
    let path = parts[1];

    // Extract body (after \r\n\r\n)
    let body = request.find("\r\n\r\n")
        .map(|i| &request[i + 4..])
        .unwrap_or("");

    let (status, response_body) = route_request(method, path, body, &sessions);

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n{}",
        status,
        response_body.len(),
        response_body
    );

    let _ = stream.write_all(response.as_bytes());
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn route_request(method: &str, path: &str, body: &str, sessions: &Sessions) -> (&'static str, String) {
    // OPTIONS preflight
    if method == "OPTIONS" {
        return ("204 No Content", String::new());
    }

    match (method, path) {
        ("GET", "/api/health") => {
            ("200 OK", r#"{"status":"ok","version":"1.0.0"}"#.to_string())
        }
        ("POST", "/api/sign") => {
            handle_create_session(body, sessions)
        }
        ("GET", p) if p.starts_with("/api/sign/") => {
            let id = &p["/api/sign/".len()..];
            handle_get_session(id, sessions)
        }
        ("PUT", p) if p.starts_with("/api/sign/") => {
            let id = &p["/api/sign/".len()..];
            handle_update_session(id, body, sessions)
        }
        ("DELETE", p) if p.starts_with("/api/sign/") => {
            let id = &p["/api/sign/".len()..];
            handle_cancel_session(id, sessions)
        }
        _ => {
            ("404 Not Found", r#"{"error":"Not found"}"#.to_string())
        }
    }
}

fn handle_create_session(body: &str, sessions: &Sessions) -> (&'static str, String) {
    let req: SignSessionRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return ("400 Bad Request", format!(r#"{{"error":"Invalid JSON: {}"}}"#, e)),
    };

    let id = generate_session_id();

    // Multi-doc: if thumbprint and data are both provided, skip cert selection
    let has_data = !req.data_base64.is_empty();
    let has_thumbprint = req.thumbprint.is_some();
    let thumbprint = req.thumbprint.clone();

    let (status, cert_base64) = if has_data && has_thumbprint {
        let tp = thumbprint.as_ref().unwrap().clone();
        match export_certificate(tp) {
            Ok(cert) => ("data_ready".to_string(), Some(cert)),
            Err(_) => ("pending".to_string(), None),
        }
    } else {
        ("pending".to_string(), None)
    };

    let session = SignSessionState {
        id: id.clone(),
        status,
        request: req,
        thumbprint,
        signature_base64: None,
        certificate_base64: cert_base64,
        error: None,
        created_at: std::time::Instant::now(),
    };

    sessions.lock().unwrap().insert(id.clone(), session);

    ("201 Created", format!(r#"{{"sessionId":"{}"}}"#, id))
}

fn handle_get_session(id: &str, sessions: &Sessions) -> (&'static str, String) {
    let map = sessions.lock().unwrap();
    match map.get(id) {
        Some(s) => {
            let json = serde_json::to_string(s).unwrap_or_default();
            ("200 OK", json)
        }
        None => ("404 Not Found", r#"{"error":"Session not found"}"#.to_string()),
    }
}

/// PUT /api/sign/{id} — Client sends dataBase64 after receiving certificate from cert_selected state.
fn handle_update_session(id: &str, body: &str, sessions: &Sessions) -> (&'static str, String) {
    #[derive(serde::Deserialize)]
    struct UpdateBody {
        #[serde(rename = "dataBase64")]
        data_base64: String,
        #[serde(rename = "hashAlgorithm", default)]
        hash_algorithm: Option<String>,
    }

    let update: UpdateBody = match serde_json::from_str(body) {
        Ok(u) => u,
        Err(e) => return ("400 Bad Request", format!(r#"{{"error":"Invalid JSON: {}"}}"#, e)),
    };

    let mut map = sessions.lock().unwrap();
    match map.get_mut(id) {
        Some(s) if s.status == "cert_selected" => {
            s.request.data_base64 = update.data_base64;
            if let Some(alg) = update.hash_algorithm {
                s.request.hash_algorithm = alg;
            }
            s.status = "data_ready".to_string();
            ("200 OK", r#"{"status":"data_ready"}"#.to_string())
        }
        Some(_) => ("409 Conflict", r#"{"error":"Session is not in cert_selected state"}"#.to_string()),
        None => ("404 Not Found", r#"{"error":"Session not found"}"#.to_string()),
    }
}

fn handle_cancel_session(id: &str, sessions: &Sessions) -> (&'static str, String) {
    let mut map = sessions.lock().unwrap();
    match map.get_mut(id) {
        Some(s) => {
            s.status = "cancelled".to_string();
            ("200 OK", r#"{"status":"cancelled"}"#.to_string())
        }
        None => ("404 Not Found", r#"{"error":"Session not found"}"#.to_string()),
    }
}

// ─── Tauri commands for HTTP session bridge ───

/// Returns the current pending or data_ready session (if any) for the frontend to display.
#[tauri::command]
fn get_pending_session(sessions: tauri::State<'_, Sessions>) -> Option<SignSessionState> {
    let map = sessions.lock().unwrap();
    // Prefer data_ready sessions (multi-doc auto-sign) over pending ones
    map.values()
        .find(|s| s.status == "data_ready")
        .or_else(|| map.values().find(|s| s.status == "pending"))
        .cloned()
}

/// Called by frontend when user selects a certificate for an HTTP session.
/// Sets status to "cert_selected" so client can retrieve the certificate and prepare data.
#[tauri::command]
fn select_cert_for_session(
    session_id: String,
    thumbprint: String,
    sessions: tauri::State<'_, Sessions>,
) -> Result<(), String> {
    let cert_base64 = export_certificate(thumbprint.clone())?;
    let mut map = sessions.lock().unwrap();
    match map.get_mut(&session_id) {
        Some(s) => {
            s.thumbprint = Some(thumbprint);
            s.certificate_base64 = Some(cert_base64);
            s.status = "cert_selected".to_string();
            Ok(())
        }
        None => Err("Session not found".to_string()),
    }
}

/// Called by frontend to sign an HTTP session's data with the selected certificate.
/// Session must be in "data_ready" state (client has sent data via PUT).
#[tauri::command]
fn sign_session(
    session_id: String,
    sessions: tauri::State<'_, Sessions>,
    window: tauri::Window,
) -> Result<(), String> {
    // Get session data
    let (data_base64, algorithm, thumbprint) = {
        let map = sessions.lock().unwrap();
        let s = map.get(&session_id).ok_or("Session not found")?;
        if s.status != "data_ready" {
            return Err(format!("Session not ready for signing (status: {})", s.status));
        }
        let tp = s.thumbprint.clone().ok_or("No certificate selected")?;
        (s.request.data_base64.clone(), s.request.hash_algorithm.clone(), tp)
    };

    // Update status to signing
    {
        let mut map = sessions.lock().unwrap();
        if let Some(s) = map.get_mut(&session_id) {
            s.status = "signing".to_string();
        }
    }

    // Decode the data
    let data = base64_decode(&data_base64)
        .map_err(|e| format!("Invalid base64 data: {}", e))?;

    // Get HWND for PIN dialog
    #[cfg(target_os = "windows")]
    let hwnd = get_tauri_window_hwnd(&window);
    #[cfg(not(target_os = "windows"))]
    let hwnd = 0usize;

    // Sign
    let sign_result = sign_hash_with_hwnd(thumbprint, base64_encode(&data), algorithm, hwnd);

    // Update session with result
    let mut map = sessions.lock().unwrap();
    if let Some(s) = map.get_mut(&session_id) {
        match sign_result {
            Ok(sig) => {
                s.signature_base64 = Some(sig);
                s.status = "signed".to_string();
            }
            Err(e) => {
                s.error = Some(e.clone());
                s.status = "error".to_string();
                return Err(e);
            }
        }
    }

    Ok(())
}

#[tauri::command]
fn cancel_sign(app: tauri::AppHandle) {
    app.exit(0);
}

fn main() {
    // Ensure protocol handler is registered
    #[cfg(windows)]
    register_protocol_handler();

    // Start HTTP server for CLI/Web communication
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    start_http_server(sessions.clone());

    tauri::Builder::default()
        .manage(sessions)
        .setup(|_app| Ok(()))
        .invoke_handler(tauri::generate_handler![
            get_certificates,
            sign_document,
            sign_hash,
            export_certificate,
            get_pending_session,
            select_cert_for_session,
            sign_session,
            cancel_sign,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(windows)]
fn register_protocol_handler() {
    use std::os::windows::process::CommandExt;

    let exe_path = std::env::current_exe().unwrap_or_default();
    let exe_str = exe_path.to_string_lossy();

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let _ = std::process::Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Classes\simplesign",
            "/ve",
            "/d",
            "URL:com.simplesign.agent protocol",
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Classes\simplesign",
            "/v",
            "URL Protocol",
            "/d",
            "",
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            r"HKCU\Software\Classes\simplesign\shell\open\command",
            "/ve",
            "/d",
            &format!(r#""{}" "%1""#, exe_str),
            "/f",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}
