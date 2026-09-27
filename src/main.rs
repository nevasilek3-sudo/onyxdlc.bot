use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
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
const PROFILE_PHOTO_PATH: &str = "assets/profile.png";

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
    KeyActivate,
    AdminFind,
    AdminDelKey,
    AdminGrant {
        user_id: Option<i64>,
    },
    AdminNewKey {
        kind: String,
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

fn cabinet_keyboard(is_admin: bool) -> InlineKeyboardMarkup {
    let mut kb = vec![
        vec![InlineKeyboardButton::callback("Купить подписку 💳", "buy")],
        vec![InlineKeyboardButton::callback("Активировать ключ 🔑", "key")],
    ];
    if is_admin {
        kb.push(vec![InlineKeyboardButton::callback("🛠 Админ-панель", "admin")]);
    }
    InlineKeyboardMarkup::new(kb)
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
        Some(Flow::KeyActivate) => {
            activate_key(&bot, chat_id, &pool, &text).await?;
        }
        Some(Flow::AdminFind) => {
            admin_find(&bot, chat_id, &pool, &cipher, &text).await?;
        }
        Some(Flow::AdminDelKey) => {
            admin_delkey(&bot, chat_id, &pool, &text).await?;
        }
        Some(Flow::AdminGrant { user_id: None }) => {
            admin_grant_target(&bot, chat_id, &pool, &flows, &text).await?;
        }
        Some(Flow::AdminGrant { user_id: Some(uid) }) => {
            flows.lock().unwrap().insert(chat_id, Flow::AdminGrant { user_id: Some(uid) });
            bot.send_message(chat_id, "Выберите тип подписки кнопками выше.").await?;
        }
        Some(Flow::AdminNewKey { kind }) => {
            flows.lock().unwrap().insert(chat_id, Flow::AdminNewKey { kind });
            bot.send_message(chat_id, "Выберите параметры кнопками выше.").await?;
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

    // Админские колбэки — отдельным обработчиком.
    let data = q.data.as_deref().unwrap_or("").to_string();
    if data == "admin"
        || data.starts_with("adm_")
        || data.starts_with("nk_")
        || data.starts_with("nu_")
        || data.starts_with("gk_")
    {
        return admin_callback(&bot, chat_id, tg_id, &pool, &flows, &cipher, &data).await;
    }

    match q.data.as_deref() {
        Some("cancel") => {
            flows.lock().unwrap().remove(&chat_id);
            bot.send_message(chat_id, "Отменено. /start — в начало.").await?;
        }
        Some("cabinet") => {
            show_cabinet(&bot, chat_id, tg_id, &pool, &cipher).await?;
        }
        Some("buy") => {
            show_shop(&bot, chat_id, &pool).await?;
        }
        Some("key") => {
            flows.lock().unwrap().insert(chat_id, Flow::KeyActivate);
            send_simple_photo(&bot, chat_id, KEYS_PHOTO_PATH, "🔑 Введите ключ активации:")
                .await?;
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
    // Фото-баннер + текст + кнопки — одним сообщением.
    let text = format!(
        "┌ Профиль ☁️\n├ Логин: {}\n├ Роль: {}\n├ Подписка: {}\n├ UID: {}\n├ ID: {}\n└ HWID: {}",
        p.username,
        role_display(&p.role),
        cabinet_sub(&p.sub_plan, p.sub_expires_at),
        shown_uid(p.id, &p.role),
        p.telegram_id,
        hwid.unwrap_or_else(|| "Не привязан".to_string()),
    );
    let kb = cabinet_keyboard(p.role == "admin");
    if Path::new(PROFILE_PHOTO_PATH).exists() {
        if bot
            .send_photo(chat_id, InputFile::file(PROFILE_PHOTO_PATH))
            .caption(&text)
            .reply_markup(kb)
            .await
            .is_ok()
        {
            return Ok(());
        }
    } else {
        log::warn!("{PROFILE_PHOTO_PATH} not found, sending text without photo");
    }
    // Запасной вариант без фото.
    bot.send_message(chat_id, text)
        .reply_markup(cabinet_keyboard(p.role == "admin"))
        .await?;
    Ok(())
}

fn cabinet_sub(plan: &str, expires_at: Option<DateTime<Utc>>) -> String {
    if plan == "none" {
        return "неактивна".to_string();
    }
    format_sub(plan, expires_at)
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

// ---------- магазин ----------

const BUY_PHOTO_PATH: &str = "assets/buy.png";
const KEYS_PHOTO_PATH: &str = "assets/keys.png";
const ADMIN_PHOTO_PATH: &str = "assets/admin.png";
const MANAGER_USERNAME: &str = "NeVasilek";

fn tariff_name(kind: &str) -> &'static str {
    match kind {
        "d30" => "30 дней",
        "d120" => "120 дней",
        "d240" => "240 дней",
        "d360" => "360 дней",
        "forever" => "Навсегда",
        "hwid" => "Сброс HWID",
        _ => "?",
    }
}

fn tariff_price(kind: &str) -> i32 {
    match kind {
        "d30" => 99,
        "d120" => 249,
        "d240" => 399,
        "d360" => 549,
        "forever" => 999,
        "hwid" => 50,
        _ => 0,
    }
}

fn tariff_days(kind: &str) -> Option<i64> {
    match kind {
        "d30" => Some(30),
        "d120" => Some(120),
        "d240" => Some(240),
        "d360" => Some(360),
        _ => None,
    }
}

fn uses_display(max_uses: i32) -> String {
    if max_uses <= 0 { "∞".to_string() } else { max_uses.to_string() }
}

async fn send_simple_photo(
    bot: &Bot,
    chat_id: ChatId,
    path: &str,
    caption: &str,
) -> ResponseResult<()> {
    if Path::new(path).exists() {
        bot.send_photo(chat_id, InputFile::file(path))
            .caption(caption)
            .reply_markup(cancel_keyboard())
            .await?;
    } else {
        bot.send_message(chat_id, caption)
            .reply_markup(cancel_keyboard())
            .await?;
    }
    Ok(())
}

async fn show_shop(bot: &Bot, chat_id: ChatId, pool: &PgPool) -> ResponseResult<()> {
    let (uid, login) = match profile_by_tg(pool, chat_id.0).await {
        Ok(Some(p)) => (shown_uid(p.id, &p.role).to_string(), p.username),
        _ => ("—".to_string(), "—".to_string()),
    };
    let caption = "🛒 Магазин\n\nПодписки:\n├ 30 дней — 99₽\n├ 120 дней — 249₽\n├ 240 дней — 399₽\n├ 360 дней — 549₽\n└ Навсегда — 999₽\n\nСброс HWID — 50₽\n\nНажмите тариф — откроется чат с менеджером и готовым текстом заказа.";
    let mut kb: Vec<Vec<InlineKeyboardButton>> = Vec::new();
    for kind in ["d30", "d120", "d240", "d360", "forever", "hwid"] {
        let label = format!("{} — {}₽", tariff_name(kind), tariff_price(kind));
        let order = format!(
            "Здравствуйте! Хочу оформить: {} ({}₽). Мой UID: {}, логин: {}, Telegram ID: {}.",
            tariff_name(kind),
            tariff_price(kind),
            uid,
            login,
            chat_id.0
        );
        let url = format!(
            "https://t.me/{MANAGER_USERNAME}?text={}",
            urlencoding::encode(&order)
        );
        match url::Url::parse(&url) {
            Ok(u) => kb.push(vec![InlineKeyboardButton::url(label, u)]),
            Err(_) => kb.push(vec![InlineKeyboardButton::callback(label, "buy")]),
        }
    }
    kb.push(vec![InlineKeyboardButton::callback("◀️ Назад", "cabinet")]);
    let markup = InlineKeyboardMarkup::new(kb);
    if Path::new(BUY_PHOTO_PATH).exists() {
        bot.send_photo(chat_id, InputFile::file(BUY_PHOTO_PATH))
            .caption(caption)
            .reply_markup(markup)
            .await?;
    } else {
        bot.send_message(chat_id, caption)
            .reply_markup(markup)
            .await?;
    }
    Ok(())
}

async fn show_cabinet(
    bot: &Bot,
    chat_id: ChatId,
    tg_id: i64,
    pool: &PgPool,
    cipher: &Cipher,
) -> ResponseResult<()> {
    match profile_by_tg(pool, tg_id).await {
        Ok(Some(p)) => {
            let hwid = p.hwid_enc.as_deref().and_then(|h| decrypt(cipher, h));
            send_cabinet(bot, chat_id, &p, hwid).await?;
        }
        _ => {
            bot.send_message(chat_id, "Нажмите /start, чтобы начать.").await?;
        }
    }
    Ok(())
}

// ---------- ключи ----------

fn gen_key_code() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    let s: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect::<String>()
        .to_uppercase();
    format!("ONYX-{}-{}", &s[..6], &s[6..])
}

/// Выдача подписки юзеру. Продлевает активную, иначе считает от сейчас.
async fn grant_sub(pool: &PgPool, user_id: i64, kind: &str) -> Result<String, sqlx::Error> {
    if kind == "forever" {
        sqlx::query(
            "UPDATE users SET sub_plan = 'forever', sub_issued_at = now(), sub_expires_at = NULL WHERE id = $1",
        )
        .bind(user_id)
        .execute(pool)
        .await?;
        return Ok("навсегда".to_string());
    }
    let days = tariff_days(kind).unwrap_or(30);
    let cur: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT sub_expires_at FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await?
            .flatten();
    let base = match cur {
        Some(e) if e > Utc::now() => e,
        _ => Utc::now(),
    };
    let exp = base + chrono::Duration::days(days);
    sqlx::query(
        "UPDATE users SET sub_plan = $1, sub_issued_at = now(), sub_expires_at = $2 WHERE id = $3",
    )
    .bind(kind)
    .bind(exp)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(format!("{} (до {})", tariff_name(kind), exp.format("%d.%m.%Y")))
}

async fn activate_key(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    code_raw: &str,
) -> ResponseResult<()> {
    let code = code_raw.trim().to_uppercase();
    let row: Option<(String, i32, i32, bool)> = sqlx::query_as(
        "SELECT kind, max_uses, used_count, revoked FROM keys WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (kind, max_uses, used_count, revoked) = match row {
        Some(r) => r,
        None => {
            bot.send_message(chat_id, "Такой ключ не найден. Проверьте код.").await?;
            return Ok(());
        }
    };
    if revoked {
        bot.send_message(chat_id, "Этот ключ отозван.").await?;
        return Ok(());
    }
    if max_uses > 0 && used_count >= max_uses {
        bot.send_message(chat_id, "У ключа закончились активации.").await?;
        return Ok(());
    }

    if kind == "hwid" {
        if let Err(e) = sqlx::query(
            "UPDATE users SET hwid_hash = NULL, hwid_enc = NULL WHERE telegram_id = $1",
        )
        .bind(chat_id.0)
        .execute(pool)
        .await
        {
            log::error!("hwid reset failed: {e}");
            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
            return Ok(());
        }
        sqlx::query("UPDATE keys SET used_count = used_count + 1, last_used_at = now() WHERE code = $1")
            .bind(&code)
            .execute(pool)
            .await
            .ok();
        bot.send_message(chat_id, "HWID сброшен ✅\nПри следующем входе с ПК привяжется новый.")
            .await?;
        return Ok(());
    }

    let user_id: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM users WHERE telegram_id = $1")
            .bind(chat_id.0)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    let user_id = match user_id {
        Some((id,)) => id,
        None => {
            bot.send_message(chat_id, "Нажмите /start, чтобы начать.").await?;
            return Ok(());
        }
    };
    match grant_sub(pool, user_id, &kind).await {
        Ok(desc) => {
            sqlx::query("UPDATE keys SET used_count = used_count + 1, last_used_at = now() WHERE code = $1")
                .bind(&code)
                .execute(pool)
                .await
                .ok();
            bot.send_message(chat_id, format!("Ключ применен ✅\nПодписка: {desc}"))
                .await?;
        }
        Err(e) => {
            log::error!("grant sub failed: {e}");
            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
        }
    }
    Ok(())
}

// ---------- админка ----------

fn admin_keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new([
        [InlineKeyboardButton::callback("👥 Найти юзера", "adm_find")],
        [InlineKeyboardButton::callback("🔑 Создать ключ", "adm_newkey")],
        [InlineKeyboardButton::callback("🗑 Удалить ключ", "adm_delkey")],
        [InlineKeyboardButton::callback("📋 Список ключей", "adm_keys")],
        [InlineKeyboardButton::callback("💳 Выдать подписку", "adm_grant")],
        [InlineKeyboardButton::callback("◀️ Назад", "cabinet")],
    ])
}

async fn require_admin(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    tg_id: i64,
) -> ResponseResult<Option<Profile>> {
    match profile_by_tg(pool, tg_id).await {
        Ok(Some(p)) if p.role == "admin" => Ok(Some(p)),
        Ok(_) => {
            bot.send_message(chat_id, "Нет доступа.").await?;
            Ok(None)
        }
        Err(e) => {
            log::error!("db error: {e}");
            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
            Ok(None)
        }
    }
}

async fn show_admin(bot: &Bot, chat_id: ChatId) -> ResponseResult<()> {
    let text = "🛠 Админ-панель\n\nВыберите раздел:";
    if Path::new(ADMIN_PHOTO_PATH).exists() {
        bot.send_photo(chat_id, InputFile::file(ADMIN_PHOTO_PATH))
            .caption(text)
            .reply_markup(admin_keyboard())
            .await?;
    } else {
        bot.send_message(chat_id, text)
            .reply_markup(admin_keyboard())
            .await?;
    }
    Ok(())
}

fn kind_buttons(prefix: &str) -> InlineKeyboardMarkup {
    let b = |t: &str, k: &str| InlineKeyboardButton::callback(t, format!("{prefix}{k}"));
    InlineKeyboardMarkup::new([
        vec![b("30 дней", "d30"), b("120 дней", "d120"), b("240 дней", "d240")],
        vec![b("360 дней", "d360"), b("Навсегда", "forever"), b("Сброс HWID", "hwid")],
        vec![InlineKeyboardButton::callback("✕ Отмена", "cancel")],
    ])
}

async fn admin_callback(
    bot: &Bot,
    chat_id: ChatId,
    tg_id: i64,
    pool: &PgPool,
    flows: &Flows,
    cipher: &Cipher,
    data: &str,
) -> ResponseResult<()> {
    if require_admin(bot, chat_id, pool, tg_id).await?.is_none() {
        return Ok(());
    }
    match data {
        "admin" => show_admin(bot, chat_id).await?,
        "adm_find" => {
            flows.lock().unwrap().insert(chat_id, Flow::AdminFind);
            bot.send_message(chat_id, "Введите UID или логин юзера:")
                .reply_markup(cancel_keyboard())
                .await?;
        }
        "adm_newkey" => {
            bot.send_message(chat_id, "Что за ключ создаем?")
                .reply_markup(kind_buttons("nk_"))
                .await?;
        }
        "adm_delkey" => {
            flows.lock().unwrap().insert(chat_id, Flow::AdminDelKey);
            bot.send_message(chat_id, "Введите код ключа для удаления:")
                .reply_markup(cancel_keyboard())
                .await?;
        }
        "adm_keys" => {
            admin_keys_list(bot, chat_id, pool).await?;
        }
        "adm_grant" => {
            flows.lock().unwrap().insert(chat_id, Flow::AdminGrant { user_id: None });
            bot.send_message(chat_id, "Кому выдаем? Введите UID или логин:")
                .reply_markup(cancel_keyboard())
                .await?;
        }
        _ if data.starts_with("nk_") => {
            let kind = data[3..].to_string();
            flows.lock().unwrap().insert(chat_id, Flow::AdminNewKey { kind: kind.clone() });
            let kb = InlineKeyboardMarkup::new([
                vec![
                    InlineKeyboardButton::callback("1", "nu_1"),
                    InlineKeyboardButton::callback("3", "nu_3"),
                    InlineKeyboardButton::callback("5", "nu_5"),
                    InlineKeyboardButton::callback("10", "nu_10"),
                    InlineKeyboardButton::callback("∞", "nu_0"),
                ],
                vec![InlineKeyboardButton::callback("✕ Отмена", "cancel")],
            ]);
            bot.send_message(chat_id, format!("Тип: {}. Сколько активаций?", tariff_name(&kind)))
                .reply_markup(kb)
                .await?;
        }
        _ if data.starts_with("nu_") => {
            let max_uses: i32 = data[3..].parse().unwrap_or(1);
            let flow = flows.lock().unwrap().remove(&chat_id);
            match flow {
                Some(Flow::AdminNewKey { kind }) => {
                    create_key(bot, chat_id, pool, tg_id, &kind, max_uses).await?;
                }
                _ => {
                    bot.send_message(chat_id, "Сначала выберите тип ключа.").await?;
                }
            }
        }
        _ if data.starts_with("gk_") => {
            let kind = data[3..].to_string();
            let flow = flows.lock().unwrap().remove(&chat_id);
            match flow {
                Some(Flow::AdminGrant { user_id: Some(uid) }) => {
                    match grant_sub(pool, uid, &kind).await {
                        Ok(desc) => {
                            bot.send_message(
                                chat_id,
                                format!("Подписка выдана ✅\nUID: {uid}\nТариф: {desc}"),
                            )
                            .await?;
                        }
                        Err(e) => {
                            log::error!("grant failed: {e}");
                            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.")
                                .await?;
                        }
                    }
                }
                _ => {
                    bot.send_message(chat_id, "Сначала введите UID или логин юзера.").await?;
                }
            }
        }
        _ => {}
    }
    let _ = cipher;
    Ok(())
}

async fn create_key(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    tg_id: i64,
    kind: &str,
    max_uses: i32,
) -> ResponseResult<()> {
    for _ in 0..5 {
        let code = gen_key_code();
        let r = sqlx::query(
            "INSERT INTO keys (code, kind, max_uses, created_by) VALUES ($1, $2, $3, $4)",
        )
        .bind(&code)
        .bind(kind)
        .bind(max_uses)
        .bind(tg_id)
        .execute(pool)
        .await;
        match r {
            Ok(_) => {
                bot.send_message(
                    chat_id,
                    format!(
                        "🔑 Ключ создан:\n{code}\nТип: {}\nАктиваций: {}",
                        tariff_name(kind),
                        uses_display(max_uses)
                    ),
                )
                .await?;
                return Ok(());
            }
            Err(e) => {
                // Возможно, коллизия кода — пробуем еще раз.
                log::warn!("key insert retry: {e}");
            }
        }
    }
    bot.send_message(chat_id, "Не получилось создать ключ, попробуйте еще раз.").await?;
    Ok(())
}

async fn admin_keys_list(bot: &Bot, chat_id: ChatId, pool: &PgPool) -> ResponseResult<()> {
    let rows: Vec<(String, String, i32, i32, bool, DateTime<Utc>)> = sqlx::query_as(
        "SELECT code, kind, max_uses, used_count, revoked, created_at
         FROM keys ORDER BY created_at DESC LIMIT 15",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    if rows.is_empty() {
        bot.send_message(chat_id, "Ключей пока нет.").await?;
        return Ok(());
    }
    let mut out = String::from("📋 Последние ключи:\n");
    for (code, kind, max_uses, used_count, revoked, created) in rows {
        let mark = if revoked { " ⛔" } else { "" };
        out.push_str(&format!(
            "\n{code} — {} — {}/{} — {}{mark}",
            tariff_name(&kind),
            used_count,
            uses_display(max_uses),
            created.format("%d.%m"),
        ));
    }
    bot.send_message(chat_id, out).await?;
    Ok(())
}

async fn admin_find(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    cipher: &Cipher,
    text: &str,
) -> ResponseResult<()> {
    let t = text.trim();
    let row: Option<(i64, i64, String, String, Option<DateTime<Utc>>, String, Option<String>, Option<String>, DateTime<Utc>)> =
        if let Ok(id) = t.parse::<i64>() {
            sqlx::query_as(
                "SELECT id, telegram_id, username, sub_plan, sub_expires_at, role, email_enc, hwid_enc, created_at
                 FROM users WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
        } else {
            sqlx::query_as(
                "SELECT id, telegram_id, username, sub_plan, sub_expires_at, role, email_enc, hwid_enc, created_at
                 FROM users WHERE username = $1",
            )
            .bind(t)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
        };
    match row {
        None => {
            bot.send_message(chat_id, "Юзер не найден.").await?;
        }
        Some((id, tg, username, sub_plan, sub_exp, role, email_enc, hwid_enc, created)) => {
            let email = email_enc
                .as_deref()
                .and_then(|e| decrypt(cipher, e))
                .unwrap_or_else(|| "—".to_string());
            let hwid = hwid_enc
                .as_deref()
                .and_then(|h| decrypt(cipher, h))
                .unwrap_or_else(|| "Не привязан".to_string());
            bot.send_message(
                chat_id,
                format!(
                    "👤 {username}\n├ UID: {id}\n├ Роль: {}\n├ Telegram: {tg}\n├ Почта: {email}\n├ Подписка: {}\n├ HWID: {hwid}\n└ Создан: {}",
                    role_display(&role),
                    cabinet_sub(&sub_plan, sub_exp),
                    created.format("%d.%m.%Y"),
                ),
            )
            .await?;
        }
    }
    Ok(())
}

async fn admin_delkey(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    text: &str,
) -> ResponseResult<()> {
    let code = text.trim().to_uppercase();
    match sqlx::query("UPDATE keys SET revoked = true WHERE code = $1")
        .bind(&code)
        .execute(pool)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            bot.send_message(chat_id, format!("Ключ {code} отозван.")).await?;
        }
        _ => {
            bot.send_message(chat_id, "Ключ не найден.").await?;
        }
    }
    Ok(())
}

async fn admin_grant_target(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    flows: &Flows,
    text: &str,
) -> ResponseResult<()> {
    let t = text.trim();
    let row: Option<(i64, String)> = if let Ok(id) = t.parse::<i64>() {
        sqlx::query_as("SELECT id, username FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
    } else {
        sqlx::query_as("SELECT id, username FROM users WHERE username = $1")
            .bind(t)
            .fetch_optional(pool)
            .await
            .unwrap_or(None)
    };
    match row {
        None => {
            bot.send_message(chat_id, "Юзер не найден. Введите UID или логин еще раз:")
                .reply_markup(cancel_keyboard())
                .await?;
            flows.lock().unwrap().insert(chat_id, Flow::AdminGrant { user_id: None });
        }
        Some((uid, username)) => {
            flows.lock().unwrap().insert(chat_id, Flow::AdminGrant { user_id: Some(uid) });
            bot.send_message(chat_id, format!("Юзер: {username} (UID {uid}). Какой тариф выдаем?"))
                .reply_markup(kind_buttons("gk_"))
                .await?;
        }
    }
    Ok(())
}
