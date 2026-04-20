use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hex::ToHex;
use sha2::{Digest, Sha256};
use rfd::FileDialog;
use pem::parse as pem_parse;
use rcgen::{Certificate, CertificateParams, PKCS_RSA_SHA256, IsCa, KeyUsagePurpose};

use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

const PRIV_KEY_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwHi5gZkIHEWMZy6AwtJbfGCE6WzlLEwzmQhyRchoMK8+/usJ
oWp8PFX9KOzXYNuxovo3qoNzfeYRj1CL0O8URojEjgiUnMifpJNyi0vLYH5J814s
a1JpcxM6GnpH/HfQbLa1qiIDXuvEkLyI4LnVNRDe4xY23RquOHoH1wpn60TGL+qb
FOgKVGowoAW/IyuoC8FfGNK6gLtGlyRHe8zu0Epza8S+xVwsbKlZrA3YRjtjH6DZ
2KniAOlJenJFa1Ie4eANd/Th9icxK3bLG+VlQGWj5t5eUdIGo3R9jGTNvTwmyjSg
oPizphm/IEh3DcHeEHEpkgMKm0PccyT5THv+VwIDAQABAoIBAALKPTYpt7phL7XX
MLqiPf1BkOupTnEj8aOIQc/NJeV+xNUBJzSVzJM7U94iAMVAqgSIyAHKwgPTL/H5
4uz2aj7TgLXmXfEf32CNWp22TY5qhjvm45HyseCfKLp1h1GbkwPgaiW7NH1NwZ2v
ffRz/Sk1w2VbTxRJbLkY28A8QGFiqWH8ToyPUXGOOsVtzkXExSZovoePzrqIJdkI
enk/IXLIF6Xaof2LU5LiIrAQiQN3WdTRsM6yAUCN3W5amtDAOno/Mc3amRf3a4CG
Zh+lexpsrcCc8pLKmfn6n6zNnZVKHYV0RMAPoo9Z8Dqlx2bOzlwJMFm3hmwsDoPW
TVc4iKECgYEA7JQBwXIiBXkUZZrvNHuUshI7qMEyT+CwLZWwLRO4JtvwFkoo08FI
oUKhaZtXhSnOmQGinWYHbngh7aPks30ZrupwFQvGI76n00qB8zE8V90BbkF68ggc
BeMp9OskrvaxzGdKlaaz2TlURNfCqUAahCs7yI8c7qQ9uwIh+vUrZIkCgYEA0EXC
+tEopTpHJ0WbM/+yMxjPS4xaRmybbutEzwctYqfyOzEps/7e9uWpvM+1fsPwe2KR
eCq8Vb3VYBc3j/LKKTyC0d/yqh+lPHqVRmN9vAheO8PrdPs/OkMX90S+ITn02J23
U6WM56H+LiJBWCeaGhKaDtjk/meI6OFudzGfU98CgYEAgQilAH6gwb1te5GKwGRb
ENjTA1MEfv68+M/4/E0SFtfE1lNyezSjyZjO8wvQK4hG77stl43LpdwOHVBT7/Xe
qUGjCkeWtW5KmPq9cAg9smqPWjSKuzHjHu7stnH+WxOgnC0GSCNZWrRjGv1XZfrZ
u5bdD6HHFP4t0S7zm65XEYkCgYBOXjGj1xgINAmaCWMBCfGvsGIv9zvwy+Ugs35M
uFKnkLJg+3rJs9mJ5Zkc5rtQW8Ida1V5dfsv+CJV6eaKT70qDw7akf3pbcbrHuUU
e1NQcYWjz3DFr9R2w9A8xq0UK46qA4579wsyDY5rJZCY7y3ZKa62b36bC7JEjq7W
QuHE2QKBgAeqO0BTWt4qhL5ksynictffepO4efXqiBdHk0iyMoXxnl1LSd/xLav1
y/TwJgu7ppMbUHgVUeaECkD4RtzBRuWms1eNOZ4yUO+h3LDSZN20VZFTCGUgTyx5
dxq3kn3rtD7ehwOeD1xevQz0Mm5BNamTgKW5zB9u1MEHRrQnKCSN
-----END RSA PRIVATE KEY-----"#;

fn main() {
    println!("RDP-Sign gestartet");

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let keypair = match load_private_key(PRIV_KEY_PEM) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Fehler beim Laden des Private Key: {}", e);
            return;
        }
    };

    ensure_publisher_cer(&exe_dir);

    let rdp_path = match get_rdp_path_from_args_or_dialog() {
        Some(p) => p,
        None => {
            println!("Keine Datei ausgewählt. Abbruch.");
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

    let signed = match sign_rdp(&content, &keypair) {
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

fn load_private_key(pem_str: &str) -> Result<RsaKeyPair, String> {
    let pem = pem_parse(pem_str).map_err(|e| format!("PEM parse error: {}", e))?;
    RsaKeyPair::from_der(&pem.contents).map_err(|e| format!("DER parse error: {:?}", e))
}

fn ensure_publisher_cer(dir: &PathBuf) {
    let cer_path = dir.join("publisher.cer");
    if cer_path.exists() {
        println!("publisher.cer gefunden.");
        return;
    }

    println!("publisher.cer nicht gefunden. Erzeuge...");

    let mut params = CertificateParams::new(vec!["RDP-Signature-Local".to_string()]);
    params.alg = &PKCS_RSA_SHA256;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let cert = Certificate::from_params(params).expect("Cert params");
    let der = cert.serialize_der().expect("Cert der");

    if let Err(e) = fs::write(&cer_path, der) {
        eprintln!("Fehler beim Schreiben von publisher.cer: {}", e);
        return;
    }

    println!("publisher.cer wurde erzeugt.");
    println!("Bitte importieren Sie diese Datei in:");
    println!("Zertifikate - Aktueller Benutzer -> Vertrauenswürdige Personen -> Zertifikate");
}

fn get_rdp_path_from_args_or_dialog() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if let Some(p) = args.pop() {
        return Some(PathBuf::from(p));
    }

    let file = FileDialog::new()
        .add_filter("RDP-Dateien", &["rdp"])
        .set_title("RDP-Datei auswählen")
        .pick_file()?;

    Some(file)
}

fn sign_rdp(content: &str, keypair: &RsaKeyPair) -> Result<String, String> {
    // Entferne alte Signaturzeilen
    let mut lines: Vec<&str> = content.lines().collect();

    lines.retain(|l| {
        let ll = l.trim_start();
        !(ll.starts_with("signature:s:")
            || ll.starts_with("signscope:s:")
            || ll.starts_with("hash:s:"))
    });

    // Scope: alle Zeilen mit ':' (wie vorher)
    let scope_lines: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| l.contains(':'))
        .collect();

    let mut scope_str = scope_lines.join("\n");
    scope_str.push('\n');

    println!("Scope extrahiert, berechne SHA256...");

    let mut hasher = Sha256::new();
    hasher.update(scope_str.as_bytes());
    let hash = hasher.finalize();
    let hash_bytes = hash.as_slice();

    println!("Signiere Hash mit RSA-PKCS1 SHA256...");

    let rng = SystemRandom::new();
    let mut sig = vec![0; keypair.public_modulus_len()];

    keypair
        .sign(&RSA_PKCS1_SHA256, &rng, hash_bytes, &mut sig)
        .map_err(|e| format!("Sign error: {:?}", e))?;

    let sig_b64 = B64.encode(&sig);
    let hash_hex = hash_bytes.encode_hex::<String>();

    println!("Füge Signaturblock hinzu...");

    let mut out = lines.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    out.push(format!("signature:s:{}", sig_b64));
    out.push(format!("signscope:s:{}", scope_lines.join(",")));
    out.push(format!("hash:s:{}", hash_hex));

    Ok(out.join("\r\n") + "\r\n")
}
