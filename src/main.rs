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
    net::Download,
    prelude::*,
    types::{ChatId, Document, InlineKeyboardButton, InlineKeyboardMarkup, InputFile},
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
    AdminNewCustom {
        uses: i32,
    },
    AdminGrantCustom {
        user_id: i64,
    },
    AdminRole {
        user_id: i64,
    },
    AdminUpload {
        name: String,
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

fn role_display(role: &str) -> String {
    match role {
        "admin" => "Администратор".to_string(),
        "media" => "Медиа".to_string(),
        "user" => "Пользователь".to_string(),
        other => other.to_string(),
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
    InlineKeyboardMarkup::new([[InlineKeyboardButton::callback("Отмена ✕", "cancel")]])
}

fn cabinet_keyboard(is_admin: bool) -> InlineKeyboardMarkup {
    let mut kb = vec![
        vec![InlineKeyboardButton::callback("Купить подписку 💳", "buy")],
        vec![InlineKeyboardButton::callback("Активировать ключ 🔑", "key")],
        vec![InlineKeyboardButton::callback("Скачать лоадер 📥", "dl")],
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

    let state = ApiState {
        pool: pool.clone(),
        cipher: cipher.clone(),
        login_fails: Arc::new(Mutex::new(HashMap::new())),
    };
    tokio::spawn(run_health_server(port, state));

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

async fn run_health_server(port: u16, state: ApiState) {
    use axum::{routing::{get, post}, Router};

    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .route("/health", get(|| async { "ok" }))
        .route("/api/auth/login", post(api_login))
        .route("/api/auth/heartbeat", post(api_heartbeat))
        .route("/api/profile", post(api_profile))
        .route("/api/dll", get(api_dll))
        .with_state(state);

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

    if let Some(doc) = msg.document() {
        return on_document(&bot, &msg, &pool, &flows, &cipher, doc).await;
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
        Some(Flow::AdminNewCustom { uses }) => {
            admin_new_custom(&bot, chat_id, &pool, tg_of(&msg), uses, &text).await?;
        }
        Some(Flow::AdminGrantCustom { user_id }) => {
            admin_grant_custom(&bot, chat_id, &pool, user_id, &text).await?;
        }
        Some(Flow::AdminRole { user_id }) => {
            admin_set_role_text(&bot, chat_id, &pool, user_id, &text).await?;
        }
        Some(Flow::AdminUpload { name }) => {
            flows.lock().unwrap().insert(chat_id, Flow::AdminUpload { name });
            bot.send_message(chat_id, "Жду файл. Пришлите документ:")
                .reply_markup(cancel_keyboard())
                .await?;
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
        || data.starts_with("cu_")
        || data.starts_with("rk_")
        || data.starts_with("au_")
        || data.starts_with("up_")
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
        Some("dl") => {
            user_download(&bot, chat_id, tg_id, &pool, &cipher).await?;
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
        "custom" => "Кастом",
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
async fn grant_sub(
    pool: &PgPool,
    user_id: i64,
    kind: &str,
    custom_hours: Option<i64>,
) -> Result<String, sqlx::Error> {
    if kind == "forever" {
        sqlx::query(
            "UPDATE users SET sub_plan = 'forever', sub_issued_at = now(), sub_expires_at = NULL WHERE id = $1",
        )
        .bind(user_id)
        .execute(pool)
        .await?;
        return Ok("навсегда".to_string());
    }
    let hours: i64 = if kind == "custom" {
        custom_hours.unwrap_or(24)
    } else {
        tariff_days(kind).unwrap_or(30) * 24
    };
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
    let exp = base + chrono::Duration::hours(hours);
    sqlx::query(
        "UPDATE users SET sub_plan = $1, sub_issued_at = now(), sub_expires_at = $2 WHERE id = $3",
    )
    .bind(kind)
    .bind(exp)
    .bind(user_id)
    .execute(pool)
    .await?;
    if kind == "custom" {
        Ok(format!("Кастом ({} ч., до {})", hours, exp.format("%d.%m.%Y %H:%M")))
    } else {
        Ok(format!("{} (до {})", tariff_name(kind), exp.format("%d.%m.%Y")))
    }
}

async fn activate_key(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    code_raw: &str,
) -> ResponseResult<()> {
    let code = code_raw.trim().to_uppercase();
    let row: Option<(String, i32, i32, bool, Option<i32>)> = sqlx::query_as(
        "SELECT kind, max_uses, used_count, revoked, duration_hours FROM keys WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (kind, max_uses, used_count, revoked, duration_hours) = match row {
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
    match grant_sub(pool, user_id, &kind, duration_hours.map(i64::from)).await {
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
        [InlineKeyboardButton::callback("Найти юзера 👥", "adm_find")],
        [InlineKeyboardButton::callback("Создать ключ 🔑", "adm_newkey")],
        [InlineKeyboardButton::callback("Удалить ключ 🗑", "adm_delkey")],
        [InlineKeyboardButton::callback("Список ключей 📋", "adm_keys")],
        [InlineKeyboardButton::callback("Выдать подписку 💳", "adm_grant")],
        [InlineKeyboardButton::callback("Залить лоадер 📤", "adm_upload")],
        [InlineKeyboardButton::callback("Назад ◀️", "cabinet")],
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
        vec![b("Кастом ⏳", "custom")],
        vec![InlineKeyboardButton::callback("Отмена ✕", "cancel")],
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
        "adm_upload" => {
            let kb = InlineKeyboardMarkup::new([
                vec![InlineKeyboardButton::callback("Лоадер", "up_loader")],
                vec![InlineKeyboardButton::callback("DLL клиента", "up_client_dll")],
                vec![InlineKeyboardButton::callback("Отмена ✕", "cancel")],
            ]);
            bot.send_message(chat_id, "Какой файл заливаем?")
                .reply_markup(kb)
                .await?;
        }
        _ if data.starts_with("up_") => {
            let name = match &data[3..] {
                "loader" => "loader",
                "client_dll" => "client_dll",
                _ => return Ok(()),
            };
            flows.lock().unwrap().insert(chat_id, Flow::AdminUpload { name: name.to_string() });
            bot.send_message(chat_id, format!("Пришлите файл ({name}) документом:"))
                .reply_markup(cancel_keyboard())
                .await?;
        }
        _ if data.starts_with("nk_") => {
            let kind = data[3..].to_string();
            if kind == "custom" {
                bot.send_message(chat_id, "Кастомный ключ: сколько активаций?")
                    .reply_markup(uses_keyboard("cu_"))
                    .await?;
            } else {
                flows.lock().unwrap().insert(chat_id, Flow::AdminNewKey { kind: kind.clone() });
                bot.send_message(chat_id, format!("Тип: {}. Сколько активаций?", tariff_name(&kind)))
                    .reply_markup(uses_keyboard("nu_"))
                    .await?;
            }
        }
        _ if data.starts_with("cu_") => {
            let uses: i32 = data[3..].parse().unwrap_or(1);
            flows.lock().unwrap().insert(chat_id, Flow::AdminNewCustom { uses });
            bot.send_message(chat_id, "На сколько часов ключ? (1–8760):")
                .reply_markup(cancel_keyboard())
                .await?;
        }
        _ if data.starts_with("rk_") => {
            // rk_<роль>_<uid>, роль без подчеркиваний.
            let rest = &data[3..];
            match rest.rsplit_once('_') {
                Some((role, id_s)) => match id_s.parse::<i64>() {
                    Ok(uid) => admin_set_role(bot, chat_id, pool, flows, uid, role).await?,
                    Err(_) => {
                        bot.send_message(chat_id, "Что-то не так, попробуйте снова.").await?;
                    }
                },
                None => {
                    bot.send_message(chat_id, "Что-то не так, попробуйте снова.").await?;
                }
            }
        }
        _ if data.starts_with("au_") => {
            let parts: Vec<&str> = data.split('_').collect();
            if parts.len() != 3 {
                return Ok(());
            }
            let uid: i64 = parts[2].parse().unwrap_or(0);
            match parts[1] {
                "grant" => {
                    let exists: Option<(i64,)> =
                        sqlx::query_as("SELECT id FROM users WHERE id = $1")
                            .bind(uid)
                            .fetch_optional(pool)
                            .await
                            .unwrap_or(None);
                    if exists.is_none() {
                        bot.send_message(chat_id, "Юзер не найден.").await?;
                        return Ok(());
                    }
                    flows.lock().unwrap().insert(chat_id, Flow::AdminGrant { user_id: Some(uid) });
                    bot.send_message(chat_id, format!("UID {uid}: какой тариф выдаем?"))
                        .reply_markup(kind_buttons("gk_"))
                        .await?;
                }
                "hwid" => {
                    match sqlx::query("UPDATE users SET hwid_hash = NULL, hwid_enc = NULL WHERE id = $1")
                        .bind(uid)
                        .execute(pool)
                        .await
                    {
                        Ok(r) if r.rows_affected() > 0 => {
                            bot.send_message(chat_id, format!("HWID сброшен (UID {uid}).")).await?;
                        }
                        _ => {
                            bot.send_message(chat_id, "Юзер не найден.").await?;
                        }
                    }
                }
                "role" => {
                    admin_role_menu(bot, chat_id, uid).await?;
                }
                "revoke" => {
                    match sqlx::query("UPDATE users SET sub_plan = 'none', sub_expires_at = NULL WHERE id = $1")
                        .bind(uid)
                        .execute(pool)
                        .await
                    {
                        Ok(r) if r.rows_affected() > 0 => {
                            bot.send_message(chat_id, format!("Подписка забрана (UID {uid}).")).await?;
                        }
                        _ => {
                            bot.send_message(chat_id, "Юзер не найден.").await?;
                        }
                    }
                }
                _ => {}
            }
        }
        _ if data.starts_with("nu_") => {
            let max_uses: i32 = data[3..].parse().unwrap_or(1);
            let flow = flows.lock().unwrap().remove(&chat_id);
            match flow {
                Some(Flow::AdminNewKey { kind }) => {
                    create_key(bot, chat_id, pool, tg_id, &kind, max_uses, None).await?;
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
                    if kind == "custom" {
                        flows.lock().unwrap().insert(chat_id, Flow::AdminGrantCustom { user_id: uid });
                        bot.send_message(chat_id, "На сколько часов выдать? (1–8760):")
                            .reply_markup(cancel_keyboard())
                            .await?;
                        return Ok(());
                    }
                    if kind == "hwid" {
                        match sqlx::query("UPDATE users SET hwid_hash = NULL, hwid_enc = NULL WHERE id = $1")
                            .bind(uid)
                            .execute(pool)
                            .await
                        {
                            Ok(r) if r.rows_affected() > 0 => {
                                bot.send_message(chat_id, format!("HWID сброшен (UID {uid}).")).await?;
                            }
                            _ => {
                                bot.send_message(chat_id, "Юзер не найден.").await?;
                            }
                        }
                        return Ok(());
                    }
                    match grant_sub(pool, uid, &kind, None).await {
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
    duration_hours: Option<i32>,
) -> ResponseResult<()> {
    for _ in 0..5 {
        let code = gen_key_code();
        let r = sqlx::query(
            "INSERT INTO keys (code, kind, max_uses, created_by, duration_hours) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&code)
        .bind(kind)
        .bind(max_uses)
        .bind(tg_id)
        .bind(duration_hours)
        .execute(pool)
        .await;
        match r {
            Ok(_) => {
                let extra = match kind {
                    "custom" => format!(" ({} ч.)", duration_hours.unwrap_or(24)),
                    _ => String::new(),
                };
                bot.send_message(
                    chat_id,
                    format!(
                        "🔑 Ключ создан:\n{code}\nТип: {}{extra}\nАктиваций: {}",
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
    let rows: Vec<(String, String, i32, i32, bool, DateTime<Utc>, Option<i32>)> = sqlx::query_as(
        "SELECT code, kind, max_uses, used_count, revoked, created_at, duration_hours
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
    for (code, kind, max_uses, used_count, revoked, created, dur) in rows {
        let mark = if revoked { " ⛔" } else { "" };
        let what = if kind == "custom" {
            format!("Кастом {}ч.", dur.unwrap_or(24))
        } else {
            tariff_name(&kind).to_string()
        };
        out.push_str(&format!(
            "\n{code} — {what} — {}/{} — {}{mark}",
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
            let kb = InlineKeyboardMarkup::new([
                vec![
                    InlineKeyboardButton::callback("Выдать сабку 💳", format!("au_grant_{id}")),
                    InlineKeyboardButton::callback("Сбросить HWID 🔄", format!("au_hwid_{id}")),
                ],
                vec![
                    InlineKeyboardButton::callback("Выдать роль 🎭", format!("au_role_{id}")),
                    InlineKeyboardButton::callback("Забрать сабку 🚫", format!("au_revoke_{id}")),
                ],
            ]);
            bot.send_message(
                chat_id,
                format!(
                    "👤 {username}\n├ UID: {id}\n├ Роль: {}\n├ Telegram: {tg}\n├ Почта: {email}\n├ Подписка: {}\n├ HWID: {hwid}\n└ Создан: {}",
                    role_display(&role),
                    cabinet_sub(&sub_plan, sub_exp),
                    created.format("%d.%m.%Y"),
                ),
            )
            .reply_markup(kb)
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

// ---------- скачивание лоадера ----------

const LOADER_FILE_NAME: &str = "ardor-gaming-rage_instrukcia_131930_22062026.pdf";

fn tg_of(msg: &Message) -> i64 {
    msg.from.as_ref().map(|u| u.id.0 as i64).unwrap_or(0)
}

fn sub_active(p: &Profile) -> bool {
    if p.sub_plan == "none" {
        return false;
    }
    if p.sub_plan == "forever" {
        return true;
    }
    p.sub_expires_at.map(|e| e > Utc::now()).unwrap_or(false)
}

fn encrypt_bytes(cipher: &Aes256Gcm, data: &[u8]) -> Vec<u8> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = cipher.encrypt(&nonce, data).expect("encryption failed");
    let mut v = nonce.to_vec();
    v.extend_from_slice(&ct);
    v
}

fn decrypt_bytes(cipher: &Aes256Gcm, raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() < 13 {
        return None;
    }
    let (n, ct) = raw.split_at(12);
    cipher.decrypt(Nonce::from_slice(n), ct).ok()
}

async fn on_document(
    bot: &Bot,
    msg: &Message,
    pool: &PgPool,
    flows: &Flows,
    cipher: &Cipher,
    doc: &Document,
) -> ResponseResult<()> {
    let chat_id = msg.chat.id;
    let waiting: Option<String> = match flows.lock().unwrap().get(&chat_id) {
        Some(Flow::AdminUpload { name }) => Some(name.clone()),
        _ => None,
    };
    let bin_name = match waiting {
        Some(n) => n,
        None => return Ok(()),
    };
    if require_admin(bot, chat_id, pool, tg_of(msg)).await?.is_none() {
        flows.lock().unwrap().remove(&chat_id);
        return Ok(());
    }
    let size = doc.file.size;
    if size == 0 || size > 20 * 1024 * 1024 {
        bot.send_message(chat_id, "Файл должен быть до 20 МБ. Пришлите другой:")
            .reply_markup(cancel_keyboard())
            .await?;
        return Ok(());
    }
    let file = match bot.get_file(&doc.file.id).await {
        Ok(f) => f,
        Err(e) => {
            log::error!("get_file failed: {e}");
            bot.send_message(chat_id, "Не скачался, попробуйте еще раз.").await?;
            return Ok(());
        }
    };
    let mut buf: Vec<u8> = Vec::new();
    if bot.download_file(&file.path, &mut buf).await.is_err() {
        bot.send_message(chat_id, "Не скачался, попробуйте еще раз.").await?;
        return Ok(());
    }
    let sha = hex::encode(Sha256::digest(&buf));
    let enc = encrypt_bytes(cipher, &buf);
    let row: Result<Option<(i32,)>, sqlx::Error> = sqlx::query_as(
        "INSERT INTO binaries (name, data, sha256, version, updated_at)
         VALUES ($1, $2, $3, 1, now())
         ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, sha256 = EXCLUDED.sha256,
             version = binaries.version + 1, updated_at = now()
         RETURNING version",
    )
    .bind(&bin_name)
    .bind(&enc)
    .bind(&sha)
    .fetch_optional(pool)
    .await;
    flows.lock().unwrap().remove(&chat_id);
    match row {
        Ok(Some((v,))) => {
            bot.send_message(
                chat_id,
                format!(
                    "Файл обновлен ✅\nЧто: {bin_name}\nРазмер: {} КБ\nSHA256: {}…\nВерсия: v{v}",
                    buf.len() / 1024,
                    &sha[..16]
                ),
            )
            .await?;
        }
        _ => {
            log::error!("binaries upsert failed");
            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
        }
    }
    Ok(())
}

async fn user_download(
    bot: &Bot,
    chat_id: ChatId,
    tg_id: i64,
    pool: &PgPool,
    cipher: &Cipher,
) -> ResponseResult<()> {
    let p = match profile_by_tg(pool, tg_id).await {
        Ok(Some(p)) => p,
        _ => {
            bot.send_message(chat_id, "Нажмите /start, чтобы начать.").await?;
            return Ok(());
        }
    };
    if !sub_active(&p) {
        bot.send_message(chat_id, "Нужна активная подписка 💳\nЗагляните в магазин.").await?;
        return Ok(());
    }
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as("SELECT data FROM binaries WHERE name = 'loader'")
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
    let bytes = match row.and_then(|(d,)| decrypt_bytes(cipher, &d)) {
        Some(b) => b,
        None => {
            bot.send_message(chat_id, "Файл пока не загружен. Обратитесь к @NeVasilek.").await?;
            return Ok(());
        }
    };
    let path = std::env::temp_dir().join(LOADER_FILE_NAME);
    if tokio::fs::write(&path, &bytes).await.is_err() {
        bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
        return Ok(());
    }
    bot.send_document(chat_id, InputFile::file(&path))
        .caption("Ваш лоадер. Переименовывать не нужно — запускайте как есть.")
        .await?;
    Ok(())
}

// ---------- роли и кастом ----------

fn uses_keyboard(prefix: &str) -> InlineKeyboardMarkup {
    let b = |t: &str, n: &str| InlineKeyboardButton::callback(t, format!("{prefix}{n}"));
    InlineKeyboardMarkup::new([
        vec![b("1", "1"), b("3", "3"), b("5", "5"), b("10", "10"), b("∞", "0")],
        vec![InlineKeyboardButton::callback("Отмена ✕", "cancel")],
    ])
}

async fn admin_role_menu(bot: &Bot, chat_id: ChatId, user_id: i64) -> ResponseResult<()> {
    let b = |t: &str, r: &str| {
        InlineKeyboardButton::callback(t, format!("rk_{r}_{user_id}"))
    };
    let kb = InlineKeyboardMarkup::new([
        vec![b("Пользователь", "user"), b("Медиа", "media"), b("Администратор", "admin")],
        vec![b("Своя ✏️", "custom")],
        vec![InlineKeyboardButton::callback("Отмена ✕", "cancel")],
    ]);
    bot.send_message(chat_id, format!("UID {user_id}: какую роль выдать?"))
        .reply_markup(kb)
        .await?;
    Ok(())
}

async fn admin_set_role(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    flows: &Flows,
    user_id: i64,
    role: &str,
) -> ResponseResult<()> {
    if role == "custom" {
        flows.lock().unwrap().insert(chat_id, Flow::AdminRole { user_id });
        bot.send_message(chat_id, "Введите название роли (1–32 символа: буквы, цифры, _, -, пробел):")
            .reply_markup(cancel_keyboard())
            .await?;
        return Ok(());
    }
    match sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(role)
        .bind(user_id)
        .execute(pool)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            bot.send_message(
                chat_id,
                format!("Роль выдана ✅\nUID: {user_id}\nРоль: {}", role_display(role)),
            )
            .await?;
        }
        _ => {
            bot.send_message(chat_id, "Юзер не найден.").await?;
        }
    }
    Ok(())
}

async fn admin_set_role_text(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    user_id: i64,
    text: &str,
) -> ResponseResult<()> {
    let role = text.trim().to_lowercase();
    let ok_len = (1..=32).contains(&role.chars().count());
    let ok_chars = role.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == ' ');
    if !ok_len || !ok_chars {
        bot.send_message(chat_id, "Роль: 1–32 символа (буквы, цифры, _, -, пробел). Еще раз:")
            .reply_markup(cancel_keyboard())
            .await?;
        return Ok(());
    }
    // Поток уже снят в on_message; просто пишем роль.
    match sqlx::query("UPDATE users SET role = $1 WHERE id = $2")
        .bind(&role)
        .bind(user_id)
        .execute(pool)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            bot.send_message(chat_id, format!("Роль выдана ✅\nUID: {user_id}\nРоль: {role}"))
                .await?;
        }
        _ => {
            bot.send_message(chat_id, "Юзер не найден.").await?;
        }
    }
    Ok(())
}

async fn admin_new_custom(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    tg_id: i64,
    uses: i32,
    text: &str,
) -> ResponseResult<()> {
    let hours: i32 = match text.trim().parse() {
        Ok(h) if (1..=8760).contains(&h) => h,
        _ => {
            bot.send_message(chat_id, "Нужно число часов от 1 до 8760. Еще раз:")
                .reply_markup(cancel_keyboard())
                .await?;
            return Ok(());
        }
    };
    // Поток уже снят; создаем ключ напрямую.
    create_key(bot, chat_id, pool, tg_id, "custom", uses, Some(hours)).await
}

async fn admin_grant_custom(
    bot: &Bot,
    chat_id: ChatId,
    pool: &PgPool,
    user_id: i64,
    text: &str,
) -> ResponseResult<()> {
    let hours: i64 = match text.trim().parse() {
        Ok(h) if (1..=8760).contains(&h) => h,
        _ => {
            bot.send_message(chat_id, "Нужно число часов от 1 до 8760. Еще раз:")
                .reply_markup(cancel_keyboard())
                .await?;
            return Ok(());
        }
    };
    match grant_sub(pool, user_id, "custom", Some(hours)).await {
        Ok(desc) => {
            bot.send_message(chat_id, format!("Подписка выдана ✅\nUID: {user_id}\nТариф: {desc}"))
                .await?;
        }
        Err(e) => {
            log::error!("grant failed: {e}");
            bot.send_message(chat_id, "Временная ошибка, попробуйте позже.").await?;
        }
    }
    Ok(())
}

// ---------- backend API для лоадера ----------

#[derive(Clone)]
struct ApiState {
    pool: PgPool,
    cipher: Cipher,
    login_fails: Arc<Mutex<HashMap<String, (u32, DateTime<Utc>)>>>,
}

#[derive(serde::Deserialize)]
struct LoginReq {
    ident: String,
    password: String,
    hwid: String,
}

#[derive(serde::Serialize)]
struct LoginResp {
    ok: bool,
    error: String,
    token: Option<String>,
    uid: Option<i64>,
    username: Option<String>,
    role: Option<String>,
    sub_plan: Option<String>,
    sub_expires_at: Option<DateTime<Utc>>,
}

#[derive(serde::Deserialize)]
struct TokenReq {
    token: String,
    hwid: String,
}

#[derive(serde::Serialize)]
struct StatusResp {
    ok: bool,
    error: String,
    uid: Option<i64>,
    username: Option<String>,
    role: Option<String>,
    sub_plan: Option<String>,
    sub_expires_at: Option<DateTime<Utc>>,
}

#[derive(serde::Deserialize)]
struct DllQuery {
    token: String,
    hwid: String,
}

fn login_fail_resp(msg: &str) -> (axum::http::StatusCode, axum::Json<LoginResp>) {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        axum::Json(LoginResp {
            ok: false,
            error: msg.to_string(),
            token: None,
            uid: None,
            username: None,
            role: None,
            sub_plan: None,
            sub_expires_at: None,
        }),
    )
}

fn plan_active(plan: &str, exp: Option<DateTime<Utc>>) -> bool {
    if plan == "none" {
        return false;
    }
    if plan == "forever" {
        return true;
    }
    exp.map(|e| e > Utc::now()).unwrap_or(false)
}

/// true = заблокировать (много неудач за 10 минут).
fn throttle_check(state: &ApiState, key: &str) -> bool {
    let mut m = state.login_fails.lock().unwrap();
    if m.len() > 2000 {
        m.clear();
    }
    let now = Utc::now();
    let e = m.entry(key.to_string()).or_insert((0, now));
    if (now - e.1).num_minutes() >= 10 {
        *e = (0, now);
    }
    e.0 >= 8
}

fn throttle_hit(state: &ApiState, key: &str) {
    let mut m = state.login_fails.lock().unwrap();
    let e = m.entry(key.to_string()).or_insert((0, Utc::now()));
    e.0 += 1;
    e.1 = Utc::now();
}

fn gen_session_token() -> (String, String) {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let token = hex::encode(b);
    let hash = sha_hex(&token);
    (token, hash)
}

async fn check_session(pool: &PgPool, token: &str, hwid: &str) -> Option<i64> {
    let h = sha_hex(token.trim());
    let row: Option<(i64, Option<String>, DateTime<Utc>)> =
        sqlx::query_as::<_, (i64, Option<String>, DateTime<Utc>)>(
            "SELECT s.user_id, u.hwid_hash, s.expires_at FROM sessions s
         JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1",
        )
        .bind(&h)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    let (uid, hwid_hash, exp) = row?;
    if exp <= Utc::now() {
        return None;
    }
    if let Some(stored) = hwid_hash {
        if stored != sha_hex(hwid.trim()) {
            return None;
        }
    }
    Some(uid)
}

async fn api_login(
    axum::extract::State(s): axum::extract::State<ApiState>,
    axum::Json(req): axum::Json<LoginReq>,
) -> impl axum::response::IntoResponse {
    use axum::http::StatusCode;
    let ident = req.ident.trim().to_string();
    if ident.is_empty() || req.password.is_empty() || req.hwid.trim().is_empty() {
        return login_fail_resp("bad request");
    }
    let key = ident.to_lowercase();
    if throttle_check(&s, &key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(LoginResp {
                ok: false,
                error: "too many attempts".to_string(),
                token: None,
                uid: None,
                username: None,
                role: None,
                sub_plan: None,
                sub_expires_at: None,
            }),
        );
    }

    let email_hash = sha_hex(&key);
    let row: Option<(i64, String, String, String, Option<DateTime<Utc>>, String)> =
        sqlx::query_as::<_, (i64, String, String, String, Option<DateTime<Utc>>, String)>(
            "SELECT id, username, password_hash, sub_plan, sub_expires_at, role FROM users
             WHERE username = $1 OR email_hash = $2",
        )
        .bind(&ident)
        .bind(&email_hash)
        .fetch_optional(&s.pool)
        .await
        .unwrap_or(None);
    let fail = || {
        throttle_hit(&s, &key);
        login_fail_resp("invalid credentials")
    };
    let (id, username, pw_hash, sub_plan, sub_exp, role) = match row {
        Some(r) => r,
        None => return fail(),
    };
    let pw = req.password.clone();
    let ok = tokio::task::spawn_blocking(move || verify_password(&pw_hash, &pw))
        .await
        .unwrap_or(false);
    if !ok {
        return fail();
    }

    // HWID: нет — привязываем, есть — сверяем.
    let hw = sha_hex(req.hwid.trim());
    let cur: Option<String> =
        sqlx::query_scalar::<_, Option<String>>("SELECT hwid_hash FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&s.pool)
            .await
            .unwrap_or(None)
            .flatten();
    match cur {
        None => {
            let enc = encrypt(&s.cipher, req.hwid.trim());
            if sqlx::query("UPDATE users SET hwid_hash = $1, hwid_enc = $2 WHERE id = $3")
                .bind(&hw)
                .bind(&enc)
                .bind(id)
                .execute(&s.pool)
                .await
                .is_err()
            {
                return login_fail_resp("temporary error");
            }
        }
        Some(stored) if stored != hw => {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(LoginResp {
                    ok: false,
                    error: "hwid_mismatch".to_string(),
                    token: None,
                    uid: None,
                    username: None,
                    role: None,
                    sub_plan: None,
                    sub_expires_at: None,
                }),
            );
        }
        _ => {}
    }

    if !plan_active(&sub_plan, sub_exp) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(LoginResp {
                ok: false,
                error: "sub_inactive".to_string(),
                token: None,
                uid: None,
                username: None,
                role: None,
                sub_plan: None,
                sub_expires_at: None,
            }),
        );
    }

    let (token, th) = gen_session_token();
    let exp = Utc::now() + chrono::Duration::hours(24);
    if sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, hwid_hash, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&th)
    .bind(id)
    .bind(&hw)
    .bind(exp)
    .execute(&s.pool)
    .await
    .is_err()
    {
        return login_fail_resp("temporary error");
    }
    (
        StatusCode::OK,
        axum::Json(LoginResp {
            ok: true,
            error: String::new(),
            token: Some(token),
            uid: Some(shown_uid(id, &role)),
            username: Some(username),
            role: Some(role),
            sub_plan: Some(sub_plan),
            sub_expires_at: sub_exp,
        }),
    )
}

async fn session_profile(
    pool: &PgPool,
    token: &str,
    hwid: &str,
) -> Option<(i64, String, String, String, Option<DateTime<Utc>>)> {
    let uid = check_session(pool, token, hwid).await?;
    let row: Option<(String, String, String, Option<DateTime<Utc>>)> =
        sqlx::query_as::<_, (String, String, String, Option<DateTime<Utc>>)>(
            "SELECT username, role, sub_plan, sub_expires_at FROM users WHERE id = $1",
        )
        .bind(uid)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);
    let (username, role, sub_plan, sub_exp) = row?;
    Some((uid, username, role, sub_plan, sub_exp))
}

async fn api_heartbeat(
    axum::extract::State(s): axum::extract::State<ApiState>,
    axum::Json(req): axum::Json<TokenReq>,
) -> impl axum::response::IntoResponse {
    use axum::http::StatusCode;
    match session_profile(&s.pool, &req.token, &req.hwid).await {
        Some((uid, username, role, sub_plan, sub_exp)) if plan_active(&sub_plan, sub_exp) => (
            StatusCode::OK,
            axum::Json(StatusResp {
                ok: true,
                error: String::new(),
                uid: Some(shown_uid(uid, &role)),
                username: Some(username),
                role: Some(role),
                sub_plan: Some(sub_plan),
                sub_expires_at: sub_exp,
            }),
        ),
        _ => (
            StatusCode::UNAUTHORIZED,
            axum::Json(StatusResp {
                ok: false,
                error: "invalid session".to_string(),
                uid: None,
                username: None,
                role: None,
                sub_plan: None,
                sub_expires_at: None,
            }),
        ),
    }
}

async fn api_profile(
    axum::extract::State(s): axum::extract::State<ApiState>,
    axum::Json(req): axum::Json<TokenReq>,
) -> impl axum::response::IntoResponse {
    api_heartbeat(axum::extract::State(s), axum::Json(req)).await
}

async fn api_dll(
    axum::extract::State(s): axum::extract::State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<DllQuery>,
) -> impl axum::response::IntoResponse {
    use axum::http::{header::CONTENT_TYPE, StatusCode};
    let uid = match check_session(&s.pool, &q.token, &q.hwid).await {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [(CONTENT_TYPE, "text/plain")],
                Vec::new(),
            );
        }
    };
    let _ = uid;
    let row: Option<(Vec<u8>,)> =
        sqlx::query_as::<_, (Vec<u8>,)>("SELECT data FROM binaries WHERE name = 'client_dll'")
            .fetch_optional(&s.pool)
            .await
            .unwrap_or(None);
    match row.and_then(|(d,)| decrypt_bytes(&s.cipher, &d)) {
        Some(bytes) => (StatusCode::OK, [(CONTENT_TYPE, "application/octet-stream")], bytes),
        None => (StatusCode::NOT_FOUND, [(CONTENT_TYPE, "text/plain")], Vec::new()),
    }
}
