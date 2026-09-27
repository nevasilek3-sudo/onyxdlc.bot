use std::path::Path;

use teloxide::{
    prelude::*,
    types::{
        ChatId, InlineKeyboardButton, InlineKeyboardMarkup, InputFile,
        MaybeInaccessibleMessage, UserId,
    },
    utils::command::BotCommands,
};

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase", description = "Доступные команды:")]
enum Command {
    #[command(description = "старт")]
    Start,
}

const WELCOME_TEXT: &str = "Привет! Добро пожаловать. Выберите действие";
const WELCOME_PHOTO_PATH: &str = "assets/welcome.png";

fn auth_keyboard() -> InlineKeyboardMarkup {
    InlineKeyboardMarkup::new([[
        InlineKeyboardButton::callback("Войти", "login"),
        InlineKeyboardButton::callback("Регистрация", "register"),
    ]])
}

// TODO: заменить на проверку по БД. Пока все считаются неавторизованными.
fn is_authorized(_user_id: UserId) -> bool {
    false
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    pretty_env_logger::init();
    log::info!("Starting bot...");

    // Render Free: нужен HTTP-порт, иначе деплой не пройдет.
    // PORT задает сам Render (дефолт 10000).
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(10000);

    tokio::spawn(run_health_server(port));

    let bot = Bot::from_env();

    let handler = Update::filter_message()
        .branch(
            dptree::entry()
                .filter_command::<Command>()
                .endpoint(answer),
        )
        .branch(Update::filter_callback_query().endpoint(on_callback));

    Dispatcher::builder(bot, handler).build().dispatch().await;
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

async fn answer(bot: Bot, msg: Message, cmd: Command) -> ResponseResult<()> {
    match cmd {
        Command::Start => {
            let authorized = msg
                .from
                .as_ref()
                .map(|u| is_authorized(u.id))
                .unwrap_or(false);
            if authorized {
                bot.send_message(msg.chat.id, "Вы уже вошли ✅").await?;
            } else {
                send_welcome(&bot, msg.chat.id).await?;
            }
        }
    }
    Ok(())
}

async fn send_welcome(bot: &Bot, chat_id: ChatId) -> ResponseResult<()> {
    let keyboard = auth_keyboard();
    if Path::new(WELCOME_PHOTO_PATH).exists() {
        bot.send_photo(chat_id, InputFile::file(WELCOME_PHOTO_PATH))
            .caption(WELCOME_TEXT)
            .reply_markup(keyboard)
            .await?;
    } else {
        // Фото не положили в assets/ — шлём тот же текст с кнопками.
        log::warn!("{WELCOME_PHOTO_PATH} not found, sending text without photo");
        bot.send_message(chat_id, WELCOME_TEXT)
            .reply_markup(keyboard)
            .await?;
    }
    Ok(())
}

async fn on_callback(bot: Bot, q: CallbackQuery) -> ResponseResult<()> {
    let text = match q.data.as_deref() {
        Some("login") => "Раздел «Войти» скоро появится.",
        Some("register") => "Раздел «Регистрация» скоро появится.",
        _ => return Ok(()),
    };
    // Убираем «часики» на кнопке.
    bot.answer_callback_query(q.id.clone()).await?;
    let chat_id = match q.message {
        Some(MaybeInaccessibleMessage::Regular(msg)) => msg.chat.id,
        _ => ChatId(q.from.id.0 as i64),
    };
    bot.send_message(chat_id, text).await?;
    Ok(())
}
