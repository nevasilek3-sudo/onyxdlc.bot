use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, Nonce, OsRng},
    Aes256Gcm,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use teloxide::{
    prelude::*,
    types::{ChatId, InlineKeyboardButton, InlineKeyboardMarkup, InputFile},
};

// ---------- константы ----------

const WELCOME_TEXT: &str = "Привет! Добро пожаловать. Выберите действие";
const WELCOME_PHOTO_PATH: &str = "assets/welcome.png";
const AUTH_PHOTO_PATH: &str = "assets/auth.png";
const PROFILE_BG_PATH: &str = "assets/background.png";
const AVATAR_DEFAULT_PATH: &str = "assets/mandarin.jpg";
const FONT_BYTES: &[u8] = include_bytes!("../assets/fonts/DejaVuSans-Bold.ttf");

// ---------- состояние диалогов (в памяти, рестарт его сбрасывает) ----------

type Flows = Arc<Mutex<HashMap<ChatId, Flow>>>;
type Cipher = Arc<Aes256Gcm>;

#[derive(Clone)]
enum Flow {
    Register {
        username: Option<String>,
        password: Option<String>,
    },
    Login {
        ident: Option<String>,
    },
}

struct Profile {
    id: i64,
    telegram_id: i64,
    username: String,
    sub_plan: String,
    sub_expires_at: Option<DateTime<Utc>>,
    role: String,
    hwid_enc: Option<String>,
}

// У админов отображаемый UID всегда 0.
fn shown_uid(id: i64, role: &str) -> i64 {
    if role == "admin" { 0 } else { id }
}

fn role_display(role: &str) -> &'static str {
    match role {
        "admin" => "Администратор",
        "media" => "Медиа",
        _ => "Пользователь",
    }
}

// ---------- клавиатуры ----------

fn auth_keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new([[
        InlineKeyboardButton::callback("Войти", "login"),
        InlineKeyboardButton::callback("Регистрация", "register"),
    ]])
}

fn cancel_keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new([[InlineKeyboardButton::callback("✕ Отмена", "cancel")]])
}

fn cabinet_keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new([[
        InlineKeyboardButton::callback("Купить подписку 💳", "buy"),
        InlineKeyboardButton::callback("Активировать ключ 🔑", "key"),
    ]])
}

// ---------- main ----------

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    pretty_env_logger::init();
    log::info!("Starting bot...");

    let key_hex = std::env::var("ENCRYPTION_KEY").expect("ENCRYPTION_KEY must be set");
    let key_bytes = hex::decode(key_hex.trim()).expect("ENCRYPTION_KEY must be hex");
    assert!(key_bytes.len() == 32, "ENCRYPTION_KEY must be 32 bytes (64 hex chars)");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    let cipher: Cipher = Arc::new(
        Aes256Gcm::new_from_slice(&arr).expect("ENCRYPTION_KEY is invalid"),
    );

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("failed to connect to Postgres");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("failed to run migrations");
    log::info!("Database ready");

    // Render Free: нужен HTTP-порт, иначе деплой не пройдет.
    // PORT задает сам Render (дефолт 10000).
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(10000);

    tokio::spawn(run_health_server(port));

    let bot = Bot::from_env();
    let flows: Flows = Arc::new(Mutex::new(HashMap::new()));

    let handler = dptree::entry()
        .branch(Update::filter_message().endpoint(on_message))
        .branch(Update::filter_callback_query().endpoint(on_callback));

    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![pool, flows, cipher])
        .build()
        .dispatch()
        .await;
}

async fn run_health_server(port: u16) {
    use axum::{routing::get, Router};

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .route("/health", get(|| async { "ok" }));

    let addr = format!("0.0.0.0:{port}");
    log::info!("Health server on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ---------- сообщения ----------

fn is_start(text: &str) -> bool {
    text == "/start" || text.starts_with("/start ") || text.starts_with("/start@")
}

async fn on_message(
    bot: Bot,
    msg: Message,
    pool: PgPool,
    flows: Flows,
    cipher: Cipher,
) -> ResponseResult<()> {
    let chat_id = msg.chat.id;
    let text = msg.text().map(|t| t.trim().to_string()).unwrap_or_default();

    if text == "/cancel" {
        flows.lock().unwrap().remove(&chat_id);
        bot.send_message(chat_id, "Отменено. /start — в начало.").await?;
        return Ok(());
    }

    if is_start(&text) {
        flows.lock().unwrap().remove(&chat_id);
        return cmd_start(&bot, &msg, &pool, &cipher).await;
    }

    if text.is_empty() {
        return Ok(());
    }

    let flow = flows.lock().unwrap().remove(&chat_id);
    match flow {
        None => {
            bot.send_message(chat_id, "Нажмите /start, чтобы начать.").await?;
        }
        Some(Flow::Register { username: None, .. }) => {
            reg_username(&bot, chat_id, &pool, &flows, &text).await?;
        }
        Some(Flow::Register { username: Some(u), password: None }) => {
            // Пароль из чата стираем сразу.
            bot.delete_message(chat_id, msg.id).await.ok();
            reg_password(&bot, chat_id, &flows, u, &text).await?;
        }
        Some(Flow::Register { username: Some(u), password: Some(p) }) => {
            reg_email(&bot, chat_id, &pool, &flows, &cipher, &msg, u, p, &text).await?;
        }
        Some(Flow::Login { ident: None }) => {
            flows.lock().unwrap().insert(
                chat_id,
                Flow::Login { ident: Some(text.clone()) },
            );
            bot.send_message(chat_id, "Введите пароль:")
                .reply_markup(cancel_keyboard())
                .await?;
        }
        Some(Flow::Login { ident: Some(ident) }) => {
            bot.delete_message(chat_id, msg.id).await.ok();
            login_password(&bot, chat_id, &pool, &flows, &cipher, ident, &text).await?;
        }
    }
    Ok(())
}

async fn cmd_start(
    bot: &Bot,
    msg: &Message,
    pool: &PgPool,
    cipher: &Cipher,
) -> ResponseResult<()> {
    let tg = msg.from.as_ref().map(|u| u.id.0 as i64);
    match tg {
        Some(tg_id) => match profile_by_tg(pool, tg_id).await {
            Ok(Some(p)) => {
                let hwid = p.hwid_enc.as_deref().and_then(|h| decrypt(cipher, h));
                send_cabinet(bot, msg.chat.id, &p, hwid).await?;
            }
            Ok(None) => send_welcome(bot, msg.chat.id).await?,
            Err(e) => {
                log::error!("db error on /start: {e}");
                bot.send_message(msg.chat.id, "Временная ошибка, попробуйте позже.")
                    .await?;
            }
        },
        None => send_welcome(bot, msg.chat.id).await?,
    }
    Ok(())
}

// ---------- колбэки ----------

async fn on_callback(
    bot: Bot,
    q: CallbackQuery,
    pool: PgPool,
    flows: Flows,
    cipher: Cipher,
) -> ResponseResult<()> {
    // Убираем «часики» на кнопке.
    bot.answer_callback_query(q.id.clone()).await?;
    let chat_id = match &q.message {
        Some(m) => m.chat().id,
        None => ChatId(q.from.id.0 as i64),
    };
    let tg_id = q.from.id.0 as i64;

    match q.data.as_deref() {
        Some("cancel") => {
            flows.lock().unwrap().remove(&chat_id);
            bot.send_message(chat_id, "Отменено. /start — в начало.").await?;
        }
        Some("buy") => {
            bot.send_message(chat_id, "Магазин подписок скоро откроется.").await?;
        }
        Some("key") => {
            bot.send_message(chat_id, "Активация ключей скоро появится.").await?;
        }
        Some("login") => {
            flows.lock().unwrap().remove(&chat_id);
            send_auth_photo(
                &bot,
                chat_id,
                "Авторизация\n\nВведите ваш логин или почту.",
            )
            .await?;
            flows.lock().unwrap().insert(chat_id, Flow::Login { ident: None });
        }
        Some("register") => {
            match telegram_has_account(&pool, tg_id).await {
                Ok(true) => {
                    bot.send_message(
                        chat_id,
                        "У вас уже есть аккаунт. Нажмите «Войти».",
                    )
                    .reply_markup(auth_keyboard())
                    .await?;
                }
                _ => {
                    flows.lock().unwrap().remove(&chat_id);
                    send_auth_photo(
                        &bot,
                        chat_id,
                        "Регистрация\n\nШаг 1/3: придумайте логин — 3–32 символа (латиница, цифры, _).",
                    )
                    .await?;
                    flows.lock().unwrap().insert(
                        chat_id,
                        Flow::Register { username: None, password: None },
                    );
                }
            }
        }
        _ => {}
    }
    let _ = cipher;
    Ok(())
}

// ---------- регистрация ----------

async fn reg_username(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    flows: &Flows,
    text: &str,
) -> ResponseResult<()> {
    if let Err(e) = validate_username(text) {
        flows.lock().unwrap().insert(
            chat_id,
            Flow::Register { username: None, password: None },
        );
        bot.send_message(chat_id, format!("{e}\n\nПопробуйте другой логин:"))
            .reply_markup(cancel_keyboard())
            .await?;
        return Ok(());
    }
    match username_taken(pool, text).await {
        Ok(true) => {
            flows.lock().unwrap().insert(
                chat_id,
                Flow::Register { username: None, password: None },
            );
            bot.send_message(chat_id, "Такой логин уже занят. Введите другой:")
                .reply_markup(cancel_keyboard())
                .await?;
        }
        Err(e) => {
            log::error!("db error: {e}");
            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
        }
        Ok(false) => {
            flows.lock().unwrap().insert(
                chat_id,
                Flow::Register { username: Some(text.to_string()), password: None },
            );
            bot.send_message(chat_id, "Шаг 2/3: придумайте пароль (минимум 8 символов).\n\nСообщение с паролем я сразу удалю из чата.")
                .reply_markup(cancel_keyboard())
                .await?;
        }
    }
    Ok(())
}

async fn reg_password(
    bot: &Bot,
    chat_id: ChatId,
    flows: &Flows,
    username: String,
    text: &str,
) -> ResponseResult<()> {
    if text.chars().count() < 8 {
        flows.lock().unwrap().insert(
            chat_id,
            Flow::Register { username: Some(username), password: None },
        );
        bot.send_message(chat_id, "Пароль слишком короткий (нужно минимум 8 символов). Введите другой:")
            .reply_markup(cancel_keyboard())
            .await?;
        return Ok(());
    }
    flows.lock().unwrap().insert(
        chat_id,
        Flow::Register { username: Some(username), password: Some(text.to_string()) },
    );
    bot.send_message(chat_id, "Шаг 3/3: введите вашу почту.")
        .reply_markup(cancel_keyboard())
        .await?;
    Ok(())
}

async fn reg_email(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    flows: &Flows,
    cipher: &Cipher,
    msg: &Message,
    username: String,
    password: String,
    text: &str,
) -> ResponseResult<()> {
    let email = text.trim().to_lowercase();
    if let Err(e) = validate_email(&email) {
        flows.lock().unwrap().insert(
            chat_id,
            Flow::Register { username: Some(username), password: Some(password) },
        );
        bot.send_message(chat_id, format!("{e}\n\nВведите почту еще раз:"))
            .reply_markup(cancel_keyboard())
            .await?;
        return Ok(());
    }
    let email_hash = sha_hex(&email);
    match email_taken(pool, &email_hash).await {
        Ok(true) => {
            flows.lock().unwrap().insert(
                chat_id,
                Flow::Register { username: Some(username), password: Some(password) },
            );
            bot.send_message(chat_id, "Эта почта уже используется. Введите другую:")
                .reply_markup(cancel_keyboard())
                .await?;
            return Ok(());
        }
        Err(e) => {
            log::error!("db error: {e}");
            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
            return Ok(());
        }
        Ok(false) => {}
    }

    // Хеш пароля считаем вне async, чтобы не стопать рантайм.
    let pw = password.clone();
    let pw_hash = match tokio::task::spawn_blocking(move || hash_password(&pw)).await {
        Ok(Ok(h)) => h,
        _ => {
            log::error!("password hashing failed");
            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
            return Ok(());
        }
    };
    let email_enc = encrypt(cipher, &email);
    let tg_id = msg.from.as_ref().map(|u| u.id.0 as i64).unwrap_or(0);

    let row: Result<Option<(i64,)>, sqlx::Error> = sqlx::query_as(
        "INSERT INTO users (telegram_id, username, password_hash, email_hash, email_enc)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(tg_id)
    .bind(&username)
    .bind(&pw_hash)
    .bind(&email_hash)
    .bind(&email_enc)
    .fetch_optional(pool)
    .await;

    match row {
        Ok(Some((id,))) => {
            let p = Profile {
                id,
                telegram_id: tg_id,
                username: username.clone(),
                sub_plan: "none".to_string(),
                sub_expires_at: None,
                role: "user".to_string(),
                hwid_enc: None,
            };
            bot.send_message(chat_id, format!("Готово! Аккаунт создан ✅\nВаш UID: {id}"))
                .await?;
            send_cabinet(bot, chat_id, &p, None).await?;
        }
        _ => {
            // Скорее всего гонка: такой логин/почта/телеграм уже заняты.
            flows.lock().unwrap().remove(&chat_id);
            bot.send_message(
                chat_id,
                "Не получилось создать аккаунт (возможно, логин или почта уже заняты). Нажмите /start и попробуйте снова.",
            )
            .await?;
        }
    }
    Ok(())
}

// ---------- вход ----------

async fn login_password(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    flows: &Flows,
    cipher: &Cipher,
    ident: String,
    password: &str,
) -> ResponseResult<()> {
    let email_hash = sha_hex(&ident.trim().to_lowercase());
    let row: Result<
        Option<(i64, i64, String, String, String, Option<DateTime<Utc>>, Option<String>)>,
        sqlx::Error,
    > = sqlx::query_as(
        "SELECT id, telegram_id, username, password_hash, sub_plan, sub_expires_at, hwid_enc
         FROM users WHERE username = $1 OR email_hash = $2",
    )
    .bind(&ident)
    .bind(&email_hash)
    .fetch_optional(pool)
    .await;

    // Роль подтягиваем отдельно, чтобы не ломать запрос, если колонки role еще нет.
    let (id, _tg_old, username, pw_hash, sub_plan, sub_exp, hwid_enc) = match row {
        Ok(Some(r)) => r,
        _ => {
            flows.lock().unwrap().remove(&chat_id);
            // Специально общая ошибка: не палим, существует ли логин.
            bot.send_message(chat_id, "Неверный логин или пароль.").await?;
            return Ok(());
        }
    };

    let pw = password.to_string();
    let h = pw_hash.clone();
    let ok = tokio::task::spawn_blocking(move || verify_password(&h, &pw))
        .await
        .unwrap_or(false);
    if !ok {
        flows.lock().unwrap().remove(&chat_id);
        bot.send_message(chat_id, "Неверный логин или пароль.").await?;
        return Ok(());
    }

    // Привязываем этот Telegram к аккаунту.
    let tg_id = chat_id.0;
    if let Err(e) = sqlx::query("UPDATE users SET telegram_id = $1 WHERE id = $2")
        .bind(tg_id)
        .bind(id)
        .execute(pool)
        .await
    {
        log::error!("bind telegram failed: {e}");
        flows.lock().unwrap().remove(&chat_id);
        bot.send_message(
            chat_id,
            "Этот Telegram уже привязан к другому аккаунту.",
        )
        .await?;
        return Ok(());
    }

    let role: String = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None)
        .unwrap_or_else(|| "user".to_string());

    flows.lock().unwrap().remove(&chat_id);
    bot.send_message(chat_id, "Вход выполнен ✅").await?;
    let p = Profile {
        id,
        telegram_id: tg_id,
        username,
        sub_plan,
        sub_expires_at: sub_exp,
        role,
        hwid_enc,
    };
    let hwid = p.hwid_enc.as_deref().and_then(|h| decrypt(cipher, h));
    send_cabinet(bot, chat_id, &p, hwid).await?;
    Ok(())
}

// ---------- личный кабинет ----------

async fn send_cabinet(
    bot: &Bot,
    chat_id: ChatId,
    p: &Profile,
    hwid: Option<String>,
) -> ResponseResult<()> {
    // 1. Фото с логином и аватаркой.
    match render_profile_image(&p.username) {
        Ok(png) => {
            let path = std::env::temp_dir().join(format!("profile_{}.png", p.telegram_id));
            if tokio::fs::write(&path, &png).await.is_ok() {
                bot.send_photo(chat_id, InputFile::file(&path)).await.ok();
            } else {
                log::warn!("cannot write profile image to temp dir");
            }
        }
        Err(e) => log::warn!("profile image skipped: {e}"),
    }

    // 2. Текст профиля + кнопки.
    let text = format!(
        "┌ Профиль ☁️\n├ Логин: {}\n├ Роль: {}\n├ Подписка: {}\n├ UID: {}\n├ ID: {}\n└ HWID: {}",
        p.username,
        role_display(&p.role),
        cabinet_sub(&p.sub_plan, p.sub_expires_at),
        shown_uid(p.id, &p.role),
        p.telegram_id,
        hwid.unwrap_or_else(|| "Не привязан".to_string()),
    );
    bot.send_message(chat_id, text)
        .reply_markup(cabinet_keyboard())
        .await?;
    Ok(())
}

fn cabinet_sub(plan: &str, expires_at: Option<DateTime<Utc>>) -> String {
    if plan == "none" {
        return "неактивна".to_string();
    }
    format_sub(plan, expires_at)
}

/// Рисует баннер кабинета: слева `> логин`, справа круглая аватарка.
fn render_profile_image(login: &str) -> Result<Vec<u8>, String> {
    use image::{imageops::FilterType, GenericImageView, Rgb};

    let bg = image::open(PROFILE_BG_PATH)
        .map_err(|e| format!("no background: {e}"))?
        .to_rgb8();
    let (w, h) = (bg.width(), bg.height());
    if w < 600 || h < 300 {
        return Err("background too small".to_string());
    }
    let mut img = bg;

    // Текст слева, как на баннере «Добро пожаловать».
    let font =
        ab_glyph::FontRef::try_from_slice(FONT_BYTES).map_err(|e| format!("no font: {e}"))?;
    let mut scale = h as f32 * 0.11;
    if login.chars().count() > 18 {
        scale *= 18.0 / login.chars().count() as f32;
    }
    imageproc::drawing::draw_text_mut(
        &mut img,
        Rgb([255u8, 255u8, 255u8]),
        (w as f32 * 0.085) as i32,
        (h as f32 * 0.31) as i32,
        scale,
        &font,
        &format!("> {login}"),
    );

    // Круглая аватарка справа.
    let av = image::open(AVATAR_DEFAULT_PATH)
        .map_err(|e| format!("no avatar: {e}"))?
        .to_rgb8();
    let d = (h as f32 * 0.34) as u32;
    let av = image::imageops::resize(&av, d, d, FilterType::Lanczos3);
    let cx = (w as f32 * 0.835) as i32;
    let cy = (h as f32 * 0.41) as i32;
    let r = d as f32 / 2.0;
    let x0 = cx - d as i32 / 2;
    let y0 = cy - d as i32 / 2;
    for y in 0..d {
        for x in 0..d {
            let dx = x as f32 - r;
            let dy = y as f32 - r;
            if dx * dx + dy * dy <= r * r {
                let (px, py) = (x0 + x as i32, y0 + y as i32);
                if px >= 0 && py >= 0 && (px as u32) < w && (py as u32) < h {
                    img.put_pixel(px as u32, py as u32, *av.get_pixel(x, y));
                }
            }
        }
    }
    // Белый ободок, как у иконки на баннере.
    let ring = ((d / 45).max(2)) as i32;
    for i in 0..ring {
        imageproc::drawing::draw_hollow_circle_mut(
            &mut img,
            (cx, cy),
            r as i32 - i,
            Rgb([255u8, 255u8, 255u8]),
        );
    }

    let mut buf = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
        .map_err(|e| format!("png encode: {e}"))?;
    Ok(buf)
}

// ---------- фото приветствия / авторизации ----------

async fn send_welcome(bot: &Bot, chat_id: ChatId) -> ResponseResult<()> {
    if Path::new(WELCOME_PHOTO_PATH).exists() {
        bot.send_photo(chat_id, InputFile::file(WELCOME_PHOTO_PATH))
            .caption(WELCOME_TEXT)
            .reply_markup(auth_keyboard())
            .await?;
    } else {
        log::warn!("{WELCOME_PHOTO_PATH} not found, sending text without photo");
        bot.send_message(chat_id, WELCOME_TEXT)
            .reply_markup(auth_keyboard())
            .await?;
    }
    Ok(())
}

async fn send_auth_photo(bot: &Bot, chat_id: ChatId, caption: &str) -> ResponseResult<()> {
    if Path::new(AUTH_PHOTO_PATH).exists() {
        bot.send_photo(chat_id, InputFile::file(AUTH_PHOTO_PATH))
            .caption(caption)
            .reply_markup(cancel_keyboard())
            .await?;
    } else {
        log::warn!("{AUTH_PHOTO_PATH} not found, sending text without photo");
        bot.send_message(chat_id, caption)
            .reply_markup(cancel_keyboard())
            .await?;
    }
    Ok(())
}

fn format_sub(plan: &str, expires_at: Option<DateTime<Utc>>) -> String {
    match plan {
        "forever" => "навсегда".to_string(),
        "d30" | "d120" | "d240" | "d360" => {
            let days_total = match plan {
                "d30" => 30,
                "d120" => 120,
                "d240" => 240,
                _ => 360,
            };
            match expires_at {
                Some(exp) => {
                    let left = (exp - Utc::now()).num_days().max(0);
                    if left <= 0 {
                        "истекла".to_string()
                    } else {
                        format!("{days_total} дней (осталось {left} дн.)")
                    }
                }
                None => format!("{days_total} дней"),
            }
        }
        _ => "нет".to_string(),
    }
}

// ---------- работа с БД ----------

async fn profile_by_tg(pool: &PgPool, tg_id: i64) -> Result<Option<Profile>, sqlx::Error> {
    let row: Option<(i64, i64, String, String, Option<DateTime<Utc>>, Option<String>)> =
        sqlx::query_as(
            "SELECT id, telegram_id, username, sub_plan, sub_expires_at, hwid_enc
             FROM users WHERE telegram_id = $1",
        )
        .bind(tg_id)
        .fetch_optional(pool)
        .await?;
    // Роль читаем отдельно, чтобы не падать, если колонки role еще нет.
    let mut out = None;
    if let Some((id, telegram_id, username, sub_plan, sub_expires_at, hwid_enc)) = row {
        let role: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
        out = Some(Profile {
            id,
            telegram_id,
            username,
            sub_plan,
            sub_expires_at,
            role: role.unwrap_or_else(|| "user".to_string()),
            hwid_enc,
        });
    }
    Ok(out)
}

async fn telegram_has_account(pool: &PgPool, tg_id: i64) -> Result<bool, sqlx::Error> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT telegram_id FROM users WHERE telegram_id = $1")
            .bind(tg_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.is_some())
}

async fn username_taken(pool: &PgPool, username: &str) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT username FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

async fn email_taken(pool: &PgPool, email_hash: &str) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT email_hash FROM users WHERE email_hash = $1")
            .bind(email_hash)
            .fetch_optional(pool)
            .await?;
    Ok(row.is_some())
}

// ---------- криптография ----------

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

fn verify_password(hash: &str, password: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn encrypt(cipher: &Aes256Gcm, plain: &str) -> String {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plain.as_bytes())
        .expect("encryption failed");
    let mut v = nonce.to_vec();
    v.extend_from_slice(&ct);
    hex::encode(v)
}

fn decrypt(cipher: &Aes256Gcm, data_hex: &str) -> Option<String> {
    let raw = hex::decode(data_hex).ok()?;
    if raw.len() < 13 {
        return None;
    }
    let (n, ct) = raw.split_at(12);
    let pt = cipher.decrypt(Nonce::from_slice(n), ct).ok()?;
    String::from_utf8(pt).ok()
}

fn sha_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

// ---------- валидация ----------

fn validate_username(s: &str) -> Result<(), &'static str> {
    let len = s.chars().count();
    if !(3..=32).contains(&len) {
        return Err("Логин должен быть 3–32 символа.");
    }
    if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Логин: только латиница, цифры и _.");
    }
    Ok(())
}

fn validate_email(s: &str) -> Result<(), &'static str> {
    if s.len() > 254 || s.contains(' ') {
        return Err("Некорректная почта.");
    }
    let mut parts = s.split('@');
    let (local, domain) = match (parts.next(), parts.next(), parts.next()) {
        (Some(l), Some(d), None) => (l, d),
        _ => return Err("Некорректная почта."),
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return Err("Некорректная почта.");
    }
    let ok = |p: &str| {
        !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || "-._+%".contains(c))
    };
    if !ok(local) || !domain.split('.').all(ok) {
        return Err("Некорректная почта.");
    }
    Ok(())
}
