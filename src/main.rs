use teloxide::{prelude::*, utils::command::BotCommands};

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase", description = "Доступные команды:")]
enum Command {
    #[command(description = "старт")]
    Start,
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

    Command::repl(bot, answer).await;
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
            bot.send_message(msg.chat.id, "Привет! Заготовка бота работает.").await?;
        }
    }
    Ok(())
}
