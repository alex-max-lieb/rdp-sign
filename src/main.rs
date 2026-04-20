use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hex::ToHex;
use rand::thread_rng;
use rsa::{pkcs1::DecodeRsaPrivateKey, pkcs1::EncodeRsaPrivateKey, pkcs8::EncodePublicKey, RsaPrivateKey, RsaPublicKey, Pkcs1v15Sign};
use sha2::{Digest, Sha256};
use rfd::FileDialog;

const PRIV_KEY_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALlqgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqgq8b
qgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqgq8bqkCAwEAAQJBAKqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqIhAP////////////////////8CIf////////////////
//////8=
-----END RSA PRIVATE KEY-----"#;

// Hinweis: Das ist ein Platzhalter.
// Wir ersetzen ihn später durch deinen echten 2048-Bit-Key.

fn main() {
    println!("RDP-Sign gestartet");

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let priv_key = ensure_private_key();
    ensure_publisher_cer(&exe_dir, &priv_key);

    let rdp_path = match get_rdp_path_from_args_or_dialog() {
        Some(p) => p,
        None => {
            println!("Keine Datei ausgewaehlt. Abbruch.");
            return;
        }
    };

    println!("Datei: {}", rdp_path.display());

    let content = match fs::read_to_string(&rdp_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Fehler beim Lesen der Datei: {}", e);
            return;
        }
    };

    let signed = match sign_rdp(&content, &priv_key) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Fehler beim Signieren: {}", e);
            return;
        }
    };

    if let Err(e) = fs::write(&rdp_path, signed) {
        eprintln!("Fehler beim Schreiben der Datei: {}", e);
        return;
    }

    println!("Signaturblock geschrieben. Fertig.");
}

fn ensure_private_key() -> RsaPrivateKey {
    if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(PRIV_KEY_PEM) {
        return k;
    }
    let mut rng = thread_rng();
    RsaPrivateKey::new(&mut rng, 2048).expect("RSA-Key-Gen fehlgeschlagen")
}

fn ensure_publisher_cer(dir: &PathBuf, priv_key: &RsaPrivateKey) {
    let cer_path = dir.join("publisher.cer");
    if cer_path.exists() {
        println!("publisher.cer gefunden.");
        return;
    }

    println!("publisher.cer nicht gefunden. Erzeuge...");

    let pub_key = RsaPublicKey::from(priv_key);
    let der_pub = pub_key.to_public_key_der().expect("PubKey DER").to_vec();

    let mut params = rcgen::CertificateParams::new(vec!["RDP-Signature-Local".to_string()]);
    params.alg = &rcgen::PKCS_RSA_SHA256;
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let cert = rcgen::Certificate::from_params(params).expect("Cert params");
    let der = cert.serialize_der().expect("Cert der");

    if let Err(e) = fs::write(&cer_path, der) {
        eprintln!("Fehler beim Schreiben von publisher.cer: {}", e);
        return;
    }

    println!("publisher.cer wurde erzeugt.");
    println!("Bitte importieren Sie diese Datei in:");
    println!("Zertifikate - Aktueller Benutzer -> Vertrauenswuerdige Personen -> Zertifikate");
    println!("Danach werden signierte RDP-Dateien ohne Warnung geoeffnet.");
}

fn get_rdp_path_from_args_or_dialog() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if let Some(p) = args.pop() {
        return Some(PathBuf::from(p));
    }

    let file = FileDialog::new()
        .add_filter("RDP-Dateien", &["rdp"])
        .set_title("RDP-Datei auswaehlen")
        .pick_file()?;

    Some(file)
}

fn sign_rdp(content: &str, priv_key: &RsaPrivateKey) -> Result<String, String> {
    let mut lines: Vec<&str> = content.lines().collect();

    lines.retain(|l| {
        let ll = l.trim_start();
        !(ll.starts_with("signature:s:") || ll.starts_with("signscope:s:") || ll.starts_with("hash:s:"))
    });

    let scope_lines: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| l.contains(':'))
        .collect();

    let scope_str = {
        let mut s = scope_lines.join("\n");
        s.push('\n');
        s
    };

    println!("Scope extrahiert, berechne SHA256...");

    let mut hasher = Sha256::new();
    hasher.update(scope_str.as_bytes());
    let hash = hasher.finalize();
    let hash_bytes = hash.as_slice();

    println!("Signiere Hash mit RSA-PKCS1...");

    let sig = priv_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), hash_bytes)
        .map_err(|e| format!("Signaturfehler: {}", e))?;

    let sig_b64 = B64.encode(&sig);
    let hash_hex = hash_bytes.encode_hex::<String>();

    println!("Fuege Signaturblock hinzu...");

    let mut out = lines.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    out.push(format!("signature:s:{}", sig_b64));
    out.push(format!("signscope:s:{}", scope_lines.join(",")));
    out.push(format!("hash:s:{}", hash_hex));

    Ok(out.join("\r\n") + "\r\n")
}
