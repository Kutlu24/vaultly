# Kasa — ekip şifre yöneticisi

Kendi sunucunuzda çalışan, uçtan uca şifreli (zero-knowledge) ekip şifre kasası.

## Özellikler
- **Zero-knowledge**: ana parola → PBKDF2 (600k) → 512 bit; yarısı kilit, yarısı sunucuya giden "auth". Sunucu yalnızca şifreli veri görür.
- **Paylaşımlı kasalar** (Sahip / Düzenleyici / Görüntüleyici), her kasanın kendi AES-256-GCM anahtarı, üye başına RSA-OAEP ile sarılı.
- **Üye çıkarılınca anahtar yenilenir** (tüm kayıtlar yeniden şifrelenir) — çıkan kişi eski anahtarla gelecekteki veriye erişemez.
- Giriş / Not / Kart kayıtları, özel alanlar, favoriler, çöp kutusu, parola geçmişi
- **TOTP (2FA) kodları** (otpauth:// destekli), parola üretici, güç ölçer
- **Güvenlik Taraması**: zayıf, tekrar eden, eski parolalar, 2FA'sız hesaplar, HIBP sızıntı kontrolü (k-anonymity)
- Davet kodlu kayıt, yönetici paneli, etkinlik kayıtları, eşzamanlı düzenleme koruması
- CSV içe aktarma (Chrome/Bitwarden/Proton/1Password) ve dışa aktarma, otomatik kilit, 30 sn pano temizleme
- Başkasına açık anahtar parmak izi doğrulaması

## Çalıştırma
```
pip install fastapi uvicorn
KASA_DATA=./data uvicorn server.main:app --port 8000     # veya: docker compose up -d
```
**HTTPS şart** (tarayıcı şifreleme API'si güvenli bağlam ister; `localhost` hariç). Örn: `tailscale serve --bg --https=8445 http://127.0.0.1:8011`.
İlk kayıt olan kişi yönetici olur; diğerleri Yönetim → Davet ile katılır.

## Testler
`node tests/e2e.mjs` (API + gerçek şifreleme), `node tests/ui.mjs` (headless Chrome). İkisi de çalışan sunucu ister (`KASA_URL`).

## Sınırlar
- Ana parola kurtarma yok (tasarım gereği). Yönetici bile sıfırlayamaz.
- Tarayıcı eklentisi / mobil uygulama / otomatik doldurma yok (sonraki adım).
- Bir üye kasayı zaten açıp kopyaladıysa, çıkarılmadan önce gördüğü parolaları değiştirmek gerekir.
- `data/secret.key` ve `kasa.db` yedeklenmeli.

## Render'a dağıtım
`render.yaml` hazır (Starter plan + 1 GB kalıcı disk, tek örnek). GitHub'a push → Render'da "New → Blueprint". Disk yedekleri için Render'daki disk snapshot'larını açık tutun ve `secret.key` + `kasa.db` dosyalarını düzenli indirip güvenli bir yere kopyalayın.
