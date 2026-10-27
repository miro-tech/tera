#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tera CF VLESS Auto Generator
GitHub Actions -> Gist

Secrets:
    GIST_TOKEN
    GIST_ID

Output:
    vless.txt
"""

import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import quote

import requests


# ============================================================
# API SETTINGS
# ============================================================

SIGN_KEY = bytes.fromhex(
    "75cf5a65d77339dfa42495306ebe6a7bb8f525b00f0f1013d47d1d5154bc7162"
)

BASES = [
    "https://megacdnedge.com/",
    "https://apiscdn.com/",
    "https://games-edge.com/",
]

API_PATH = "/v1/configs"
APP_VERSION = "0"

ENC_KEY_HEX = (
    "70b6703df2401202d79e865321d8517ba756808713f17d675ed22ed61b139dc7"
)

OUTPUT_FILE = "vless.txt"
GIST_FILENAME = "vless.txt"

GITHUB_API = "https://api.github.com"


# ============================================================
# GIST SETTINGS
# ============================================================

GIST_TOKEN = os.environ.get("GIST_TOKEN", "").strip()
GIST_ID = os.environ.get("GIST_ID", "").strip()


# ============================================================
# VALIDATION
# ============================================================

def check_settings():
    if not GIST_TOKEN:
        raise RuntimeError("Не задан GitHub Secret GIST_TOKEN")

    if not GIST_ID:
        raise RuntimeError("Не задан GitHub Secret GIST_ID")

    try:
        key = bytes.fromhex(ENC_KEY_HEX)
    except ValueError as exc:
        raise RuntimeError("ENC_KEY_HEX содержит неверный HEX") from exc

    if len(SIGN_KEY) == 0:
        raise RuntimeError("SIGN_KEY пустой")

    if len(key) != 32:
        raise RuntimeError("AES-256-GCM требует ключ длиной 32 байта")

    return key


# ============================================================
# OPENSSL
# ============================================================

def load_libcrypto():
    candidates = [
        ctypes.util.find_library("crypto"),
        "libcrypto.so.3",
        "libcrypto.so.1.1",
        "libcrypto.so",
    ]

    for name in candidates:
        if not name:
            continue

        try:
            lib = ctypes.CDLL(name)

            required = [
                "EVP_CIPHER_CTX_new",
                "EVP_CIPHER_CTX_free",
                "EVP_aes_256_gcm",
                "EVP_DecryptInit_ex",
                "EVP_DecryptUpdate",
                "EVP_DecryptFinal_ex",
                "EVP_CIPHER_CTX_ctrl",
            ]

            if all(hasattr(lib, symbol) for symbol in required):
                return lib

        except OSError:
            continue

    raise RuntimeError("Не удалось загрузить OpenSSL libcrypto")


def decrypt_gcm(iv_b64, ct_b64, key):
    """
    AES-256-GCM.

    iv: Base64 IV
    ct: Base64(ciphertext + 16-byte authentication tag)
    AAD: /v1/configs
    """

    lib = load_libcrypto()

    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_new.argtypes = []

    lib.EVP_CIPHER_CTX_free.restype = None
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

    lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
    lib.EVP_aes_256_gcm.argtypes = []

    lib.EVP_DecryptInit_ex.restype = ctypes.c_int
    lib.EVP_DecryptInit_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]

    lib.EVP_DecryptUpdate.restype = ctypes.c_int
    lib.EVP_DecryptUpdate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_void_p,
        ctypes.c_int,
    ]

    lib.EVP_DecryptFinal_ex.restype = ctypes.c_int
    lib.EVP_DecryptFinal_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    ]

    lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
    ]

    iv = base64.b64decode(iv_b64, validate=True)
    raw = base64.b64decode(ct_b64, validate=True)

    if len(key) != 32:
        raise ValueError("AES-256 key должен иметь длину 32 байта")

    if not iv:
        raise ValueError("Пустой IV")

    if len(raw) < 16:
        raise ValueError("Ciphertext слишком короткий: отсутствует GCM tag")

    ciphertext = raw[:-16]
    tag = raw[-16:]
    aad = API_PATH.encode("utf-8")

    ctx = lib.EVP_CIPHER_CTX_new()

    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new() failed")

    try:
        ret = lib.EVP_DecryptInit_ex(
            ctx, lib.EVP_aes_256_gcm(), None, None, None
        )

        if ret != 1:
            raise RuntimeError("EVP_DecryptInit_ex cipher failed")

        # EVP_CTRL_AEAD_SET_IVLEN = 0x9
        ret = lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(iv), None)

        if ret != 1:
            raise RuntimeError("Не удалось установить длину IV")

        key_buf = ctypes.create_string_buffer(key, len(key))
        iv_buf = ctypes.create_string_buffer(iv, len(iv))

        ret = lib.EVP_DecryptInit_ex(
            ctx, None, None, key_buf, iv_buf
        )

        if ret != 1:
            raise RuntimeError("EVP_DecryptInit_ex key/iv failed")

        aad_buf = ctypes.create_string_buffer(aad, len(aad))
        aad_len = ctypes.c_int(0)

        ret = lib.EVP_DecryptUpdate(
            ctx,
            None,
            ctypes.byref(aad_len),
            aad_buf,
            len(aad),
        )

        if ret != 1:
            raise RuntimeError("Не удалось передать AAD")

        out_buf = ctypes.create_string_buffer(len(ciphertext) + 16)
        out_len = ctypes.c_int(0)

        if ciphertext:
            ct_buf = ctypes.create_string_buffer(
                ciphertext, len(ciphertext)
            )

            ret = lib.EVP_DecryptUpdate(
                ctx,
                out_buf,
                ctypes.byref(out_len),
                ct_buf,
                len(ciphertext),
            )

            if ret != 1:
                raise RuntimeError("EVP_DecryptUpdate failed")

        dec_len = out_len.value

        tag_buf = ctypes.create_string_buffer(tag, len(tag))

        # EVP_CTRL_AEAD_SET_TAG = 0x11
        ret = lib.EVP_CIPHER_CTX_ctrl(
            ctx, 0x11, len(tag), tag_buf
        )

        if ret != 1:
            raise RuntimeError("Не удалось установить GCM tag")

        final_len = ctypes.c_int(0)

        final_ptr = ctypes.cast(
            ctypes.byref(out_buf, dec_len),
            ctypes.c_void_p,
        )

        ret = lib.EVP_DecryptFinal_ex(
            ctx, final_ptr, ctypes.byref(final_len)
        )

        if ret != 1:
            raise ValueError(
                "AES-GCM: неверный tag, IV, ключ или AAD"
            )

        plaintext = out_buf.raw[:dec_len + final_len.value]

        return plaintext.decode("utf-8")

    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


# ============================================================
# EXTRACT ENCRYPTED DATA
# ============================================================

def extract_encrypted_data(response):
    try:
        obj = response.json()
    except Exception as exc:
        raise ValueError(
            "Ответ API не является JSON: " + response.text[:300]
        ) from exc

    def find_values(value):
        if isinstance(value, dict):
            iv = (
                value.get("iv")
                or value.get("IV")
                or value.get("nonce")
            )

            ct = (
                value.get("ct")
                or value.get("ciphertext")
                or value.get("cipher")
                or value.get("encrypted")
                or value.get("payload")
            )

            if (
                isinstance(iv, str)
                and isinstance(ct, str)
                and iv
                and ct
            ):
                return iv, ct

            for child in value.values():
                result = find_values(child)

                if result:
                    return result

        elif isinstance(value, list):
            for child in value:
                result = find_values(child)

                if result:
                    return result

        return None

    result = find_values(obj)

    if not result:
        print("[API] Не удалось найти IV и ciphertext")
        print(json.dumps(obj, indent=2, ensure_ascii=False)[:3000])
        raise ValueError("IV/ciphertext отсутствуют в ответе API")

    return result


# ============================================================
# FETCH CONFIG
# ============================================================

def fetch_config(enc_key):
    session = requests.Session()

    headers_base = {
        "Accept": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 13) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/120.0 Mobile Safari/537.36"
        ),
    }

    errors = []

    for base in BASES:
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)

        payload = f"GET\n{API_PATH}\n{ts}\n{nonce}"

        signature = hmac.new(
            SIGN_KEY,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        headers = {
            **headers_base,
            "X-Ts": ts,
            "X-Nonce": nonce,
            "X-Sign": signature,
            "X-App-Ver": APP_VERSION,
        }

        url = base.rstrip("/") + API_PATH

        print(f"\n[API] {url}")

        try:
            response = session.get(
                url,
                headers=headers,
                timeout=(10, 20),
                allow_redirects=False,
            )

            print(f"[API] HTTP {response.status_code}")

            if response.status_code != 200:
                print("[API] Ответ:", response.text[:300])
                errors.append(f"{base}: HTTP {response.status_code}")
                continue

            iv_b64, ct_b64 = extract_encrypted_data(response)

            print("[API] IV найден")
            print("[API] Ciphertext найден")
            print("[CRYPTO] AES-256-GCM расшифровка...")

            plaintext = decrypt_gcm(iv_b64, ct_b64, enc_key)

            try:
                data = json.loads(plaintext)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Расшифрованные данные не JSON: {exc}"
                ) from exc

            if not isinstance(data, dict):
                raise ValueError("Расшифрованный JSON должен быть объектом")

            print("[CRYPTO] Расшифровка успешна")
            print("[API] Поля:", ", ".join(sorted(data.keys())))

            return data

        except Exception as exc:
            message = f"{base}: {type(exc).__name__}: {exc}"
            errors.append(message)
            print("[ERROR]", message)

    raise RuntimeError(
        "Все API-зеркала завершились ошибкой:\n"
        + "\n".join(errors)
    )


# ============================================================
# GENERATE VLESS LINKS
# ============================================================

def generate_configs(data):
    hosts = data.get("hosts") or []
    ips = data.get("clean_ips") or []
    template = data.get("template")

    if not isinstance(template, str) or not template:
        raise ValueError("В ответе API отсутствует template")

    if not isinstance(hosts, list) or not isinstance(ips, list):
        raise ValueError("hosts и clean_ips должны быть списками")

    if not hosts and not ips:
        raise ValueError("В JSON отсутствуют hosts и clean_ips")

    results = []

    if ips and hosts:
        pairs = (
            (str(ip), str(host))
            for ip in ips
            for host in hosts
        )
    else:
        targets = hosts if hosts else ips

        pairs = (
            (str(target), str(target))
            for target in targets
        )

    for ip, host in pairs:
        link = (
            template
            .replace("__IP__", ip)
            .replace("__HOST__", host)
        )

        short_name = host.split(".")[0]

        for marker in (
            "#Tera-CF-Patt",
            "#Tera-Reality-Vision",
        ):
            if marker in link:
                link = link.replace(
                    marker,
                    marker + "-" + short_name,
                )
                break

        if "__HOST__" in link or "__IP__" in link:
            raise ValueError("Остался необработанный плейсхолдер")

        if not link.startswith("vless://"):
            raise ValueError("Шаблон сгенерировал ссылку не формата vless://")

        results.append(link)

    results = list(dict.fromkeys(results))

    if not results:
        raise ValueError("Не удалось сгенерировать VLESS-ссылки")

    return results


# ============================================================
# SAVE LOCAL FILE
# ============================================================

def save_configs(results):
    output = Path(OUTPUT_FILE).resolve()

    output.write_text(
        "\n".join(results) + "\n",
        encoding="utf-8",
    )

    print(f"[FILE] Сохранено: {output}")

    return output


# ============================================================
# UPDATE EXISTING GIST
# ============================================================

def update_gist(content):
    session = requests.Session()

    session.headers.update({
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GIST_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Tera-CF-VLESS-Automation",
    })

    url = f"{GITHUB_API}/gists/{GIST_ID}"

    payload = {
        "files": {
            GIST_FILENAME: {
                "content": content,
            }
        }
    }

    print(f"\n[GIST] Обновление Gist: {GIST_ID}")

    response = session.patch(
        url,
        json=payload,
        timeout=30,
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Gist API HTTP {response.status_code}: "
            f"{response.text[:1000]}"
        )

    gist = response.json()

    files = gist.get("files") or {}
    file_info = files.get(GIST_FILENAME) or {}

    html_url = gist.get("html_url")
    raw_url = file_info.get("raw_url")

    if not raw_url:
        raise RuntimeError(
            f"GitHub не вернул raw_url для {GIST_FILENAME}"
        )

    Path("gist_url.txt").write_text(
        f"GIST_ID={GIST_ID}\n"
        f"GIST_URL={html_url or ''}\n"
        f"RAW_URL={raw_url}\n",
        encoding="utf-8",
    )

    print("\n========== GIST UPDATED ==========")
    print("GIST_ID:", GIST_ID)
    print("GIST_URL:", html_url)
    print("RAW_URL:", raw_url)
    print("==================================")

    return raw_url


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 60)
    print("TERA CF VLESS AUTO GENERATOR")
    print("=" * 60)

    enc_key = check_settings()

    data = fetch_config(enc_key)
    results = generate_configs(data)

    content = "\n".join(results) + "\n"

    save_configs(results)
    update_gist(content)

    print("\n========== STATISTICS ==========")
    print("MODE:    ", data.get("mode", "unknown"))
    print("CDN:     ", data.get("cdn", "unknown"))
    print("CLEAN IP:", len(data.get("clean_ips") or []))
    print("HOSTS:   ", len(data.get("hosts") or []))
    print("CONFIGS: ", len(results))
    print("OUTPUT:  ", Path(OUTPUT_FILE).resolve())
    print("================================")

    print("\n=== FIRST 3 CONFIGS ===")

    for index, link in enumerate(results[:3], 1):
        print(f"\n[{index}] {link}")

    print("\n[DONE] Gist успешно обновлён")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[STOP] Остановлено пользователем")
        sys.exit(130)
    except Exception as exc:
        print(f"\n[FATAL] {type(exc).__name__}: {exc}")
        sys.exit(1)
