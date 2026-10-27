# Arsipin API

Backend REST terpisah untuk frontend Arsipin. API memakai Node.js, Express, Prisma, dan PostgreSQL. `DATABASE_URL` hanya dikonfigurasi pada service backend.

## Menjalankan lokal

Butuh Node.js 22+ dan PostgreSQL.

1. Salin `.env.example` menjadi `.env`, lalu isi `DATABASE_URL` dan `SESSION_SECRET`.
2. Instal dependensi: `npm install`.
3. Buat Prisma Client dan terapkan migrasi: `npm run db:generate` lalu `npm run db:migrate`.
4. Jalankan backend: `npm run dev` (atau `npm start`).

API berjalan pada `http://localhost:4000`. Tambahkan origin lengkap frontend ke `FRONTEND_ORIGINS`; jika beberapa origin, pisahkan dengan koma. CORS mengizinkan credentials, sehingga frontend harus memakai `credentials: "include"`.

Untuk Google OAuth, buat OAuth client di Google Cloud. Atur `GOOGLE_CALLBACK_URL` sebagai Authorized redirect URI yang sama persis, biasanya `http://localhost:4000/auth/google/callback`, lalu isi `GOOGLE_CLIENT_ID` dan `GOOGLE_CLIENT_SECRET`. Frontend memulai alur melalui `GET /auth/google?returnTo=<frontend-url>`. `returnTo` hanya diterima bila origin-nya tercantum di `FRONTEND_ORIGINS`; route dan query di origin yang diizinkan tetap dapat dipakai.

Saat frontend dan API berada pada site berbeda, set `COOKIE_SAME_SITE=none` dan `COOKIE_SECURE=true` serta gunakan HTTPS. Untuk development lokal, `lax` dan `COOKIE_SECURE=false` cukup. Cookie sesi selalu HTTP-only. Ganti `SESSION_SECRET` dengan nilai acak minimal 32 karakter sebelum menjalankan service.

## Endpoint

- `GET /auth/session` — `{ "user": null }` atau data pengguna aktif.
- `POST /auth/login` — body `{ "identifier", "password" }`; login dengan email atau username.
- `POST /auth/register` — body `{ "username", "email", "password", "passwordConfirmation" }`; membuat akun dan sesi.
- `POST /auth/logout` — mencabut sesi dan menghapus cookie.
- `GET /auth/google?returnTo=...` — memulai login Google. Callback OAuth backend: `GET /auth/google/callback`.
- `GET /documents?q=&status=&page=1&limit=10` — daftar dokumen milik pengguna, difilter judul/status, dengan pagination.
- `POST /documents` — body `{ "judul", "isi" }`; membuat dokumen DRAFT dan versi awal.
- `GET /documents/:id` — membaca dokumen yang dimiliki pengguna.
- `POST /documents/:id/versions` — body `{ "judul", "isi", "ringkasan" }`; menambahkan revisi.

Semua endpoint dokumen membutuhkan sesi. Pengguna hanya dapat membaca atau merevisi dokumen miliknya. Revisi dibatasi ke dokumen berstatus `DRAFT`. Versi baru memperoleh nomor berikutnya dan menjadi versi aktif; baris versi lama tidak diubah. PostgreSQL juga menolak operasi `UPDATE` atau `DELETE` pada tabel versi.

Error API memakai `{ "message": "..." }`. Status yang umum: `400` input tidak valid, `401` sesi tidak ada/tidak valid, `403` dokumen bukan milik pengguna, `404` dokumen tidak ditemukan, `409` konflik data/status, dan `503` OAuth belum dikonfigurasi.
