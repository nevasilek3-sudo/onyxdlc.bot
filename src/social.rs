//! Authenticated relay. Game positions are client reports, not Minecraft-server attestation.
use super::{ApiState, check_session};
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::{HashMap, VecDeque}, time::{Duration, Instant}};

#[derive(Default)]
pub(super) struct Relay {
    peers: HashMap<i64, Peer>,
    events: VecDeque<Event>,
    projectiles: HashMap<String, Projectile>,
    sequence: u64,
    requests: HashMap<i64, Instant>,
}
struct Peer {
    presence: Presence,
    username: String,
    seen: Instant,
    last_sync: Instant,
    last_throw: Option<Instant>,
}
struct Projectile { owner: i64, room: String, dimension: String, start: [f64; 3], velocity: [f64; 3], created: Instant }
struct Event { id: u64, room: Option<String>, dimension: String, kind: &'static str, data: Value, created: Instant }

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Presence {
    #[serde(default)] pub game_uuid: String,
    #[serde(default)] pub game_name: String,
    #[serde(default)] pub room: String,
    #[serde(default)] pub dimension: String,
    #[serde(default)] pub position: [f64; 3],
    #[serde(default)] pub snow: bool,
    #[serde(default)] pub cosmetics: bool,
    #[serde(default)] pub irc: bool,
    #[serde(default)] pub equipped: Vec<i32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    token: String, hwid: String,
    #[serde(default)] presence: Presence,
    #[serde(default)] cursor: u64,
    #[serde(default)] operations: Vec<Value>,
    #[serde(default)] leave: bool,
}

fn uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i,b)| if [8,13,18,23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() })
}
fn finite(v: [f64;3]) -> bool { v.iter().all(|n| n.is_finite() && n.abs() <= 30_000_000.0) }
fn distance(a: [f64;3], b: [f64;3]) -> f64 { (0..3).map(|i| (a[i]-b[i]).powi(2)).sum::<f64>().sqrt() }
fn vector(v: Option<&Value>) -> Option<[f64;3]> {
    let a = v?.as_array()?;
    if a.len() != 3 { return None; }
    let result = [a[0].as_f64()?, a[1].as_f64()?, a[2].as_f64()?];
    finite(result).then_some(result)
}
fn plain(text: &str, max: usize) -> bool { !text.is_empty() && text.chars().count() <= max && !text.chars().any(|c| c.is_control() || c == '§' || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) }
fn cosmetic_allowed(id: i32) -> bool { (0..=62).contains(&id) && ![2,11,12,13,26,50,54,55].contains(&id) }
fn role_label(role: &str) -> &str { match role { "admin" => "Administrator", "media" => "Media", "developer" => "Developer", _ => "User" } }
fn can_manage(actor: i64, role: &str, target: i64, kind: &str) -> bool {
    role == "admin" || (kind == "prefix" && actor == target)
}
fn target_uid(target: &str) -> Option<i64> {
    let value = target.strip_prefix("uid:").or_else(|| target.strip_prefix('#')).unwrap_or(target);
    value.parse::<i64>().ok().filter(|id| *id > 0)
}
fn prefix_allowed(text: &str, role: &str) -> bool {
    if text.is_empty() { return true; }
    if !plain(text,24) || text.chars().any(|c| !c.is_ascii_alphanumeric() && c != ' ' && c != '_' && c != '-') { return false; }
    let normalized: String = text.chars().filter(|c| c.is_ascii_alphanumeric()).flat_map(char::to_lowercase).collect();
    (role == "admin" || role == "developer" || !["admin", "developer", "owner", "staff", "moderator"].iter().any(|r| normalized.contains(r)))
        && (role == "media" || role == "admin" || role == "developer" || !normalized.contains("media"))
}

impl Relay {
    fn emit(&mut self, room: Option<String>, dimension: String, kind: &'static str, data: Value) {
        self.sequence += 1;
        self.events.push_back(Event { id:self.sequence, room, dimension, kind, data, created:Instant::now() });
        while self.events.len() > 512 { self.events.pop_front(); }
    }
    fn prune(&mut self) {
        self.requests.retain(|_,t| t.elapsed() < Duration::from_secs(60));
        self.peers.retain(|_,p| p.seen.elapsed() < Duration::from_secs(15));
        self.projectiles.retain(|_,p| p.created.elapsed() < Duration::from_secs(8));
        while self.events.front().is_some_and(|e| e.created.elapsed() > Duration::from_secs(60)) { self.events.pop_front(); }
    }
}

pub(super) async fn sync(State(state): State<ApiState>, Json(mut req): Json<Request>) -> (StatusCode, Json<Value>) {
    let Some(uid) = check_session(&state.pool, &req.token, &req.hwid).await else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"ok":false,"error":"invalid session"})));
    };
    {
        let Ok(mut relay) = state.social.lock() else { return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"error":"relay"}))); };
        relay.prune();
        if relay.requests.get(&uid).is_some_and(|t| t.elapsed() < Duration::from_millis(150)) {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"ok":false,"error":"rate limit"})));
        }
        if relay.requests.len() >= 5000 && !relay.requests.contains_key(&uid) {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"error":"capacity"})));
        }
        relay.requests.insert(uid,Instant::now());
    }
    let profile = sqlx::query_as::<_, (String,String)>("SELECT username, role FROM users WHERE id=$1")
        .bind(uid).fetch_one(&state.pool).await;
    let Ok((username, role)) = profile else { return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"error":"database"}))); };
    let Ok((prefix, banned)) = sqlx::query_as::<_, (String,bool)>(
        "SELECT COALESCE((SELECT prefix FROM social_profiles WHERE user_id=$1), ''), COALESCE((SELECT irc_banned FROM social_profiles WHERE user_id=$1), false)")
        .bind(uid).fetch_one(&state.pool).await else { return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"error":"database"}))); };
    if req.operations.len() > 16 || req.presence.room.len() > 128 || req.presence.dimension.len() > 128
        || req.presence.game_name.len() > 32 || !finite(req.presence.position) || req.presence.equipped.len() > 8 {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok":false,"error":"invalid request"})));
    }
    if !req.presence.game_uuid.is_empty() && !uuid(&req.presence.game_uuid) {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok":false,"error":"invalid uuid"})));
    }
    req.presence.equipped.retain(|id| cosmetic_allowed(*id));
    req.presence.equipped.sort_unstable(); req.presence.equipped.dedup();
    if !req.presence.cosmetics { req.presence.equipped.clear(); }
    let mut replies: Vec<String> = Vec::new();
    // Actor and role always come from the authenticated server-side profile.
    for op in &req.operations {
        let kind = op["type"].as_str().unwrap_or("");
        if !["prefix","mute","ban","unban"].contains(&kind) { continue; }
        let target = op["user"].as_str().unwrap_or("");
        let target_row = if target.is_empty() { Ok(Some((uid,role.clone()))) } else {
            sqlx::query_as::<_, (i64,String)>("SELECT id, role FROM users WHERE id=$2 OR lower(username)=lower($1) ORDER BY (id=$2) DESC NULLS LAST LIMIT 1")
                .bind(target).bind(target_uid(target)).fetch_optional(&state.pool).await
        };
        let Ok(Some((target_id,target_role))) = target_row else { replies.push("Пользователь не найден".into()); continue; };
        if !can_manage(uid,&role,target_id,kind) { replies.push("Недостаточно прав".into()); continue; }
        let mut tx = match state.pool.begin().await { Ok(tx) => tx, Err(_) => { replies.push("Ошибка базы данных".into()); continue; } };
        let result = if kind == "prefix" {
            let text = op["text"].as_str().unwrap_or("");
            if !prefix_allowed(text,&target_role) {
                replies.push("Недопустимый или служебный префикс".into()); continue;
            }
            sqlx::query("INSERT INTO social_profiles(user_id,prefix) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET prefix=$2,updated_at=now()")
                .bind(target_id).bind(text).execute(&mut *tx).await
        } else if kind == "mute" {
            let minutes = op["minutes"].as_i64().unwrap_or(-1);
            if !(0..=10080).contains(&minutes) { replies.push("Мут: от 0 до 10080 минут".into()); continue; }
            sqlx::query("INSERT INTO social_profiles(user_id,muted_until) VALUES($1,now()+$2 * interval '1 minute') ON CONFLICT(user_id) DO UPDATE SET muted_until=now()+$2 * interval '1 minute',updated_at=now()")
                .bind(target_id).bind(minutes as f64).execute(&mut *tx).await
        } else {
            sqlx::query("INSERT INTO social_profiles(user_id,irc_banned) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET irc_banned=$2,updated_at=now()")
                .bind(target_id).bind(kind == "ban").execute(&mut *tx).await
        };
        if result.is_ok() && sqlx::query("INSERT INTO social_audit(actor,target,action) VALUES($1,$2,$3)")
            .bind(uid).bind(target_id).bind(kind).execute(&mut *tx).await.is_ok() && tx.commit().await.is_ok() {
            replies.push("Сохранено".into());
        } else { replies.push("Ошибка базы данных".into()); }
    }
    // Claim the chat interval in PostgreSQL, so reconnects/restarts cannot reset it.
    let mut accepted_chat = None;
    for op in &req.operations {
        if op["type"].as_str() != Some("chat") || !req.presence.irc { continue; }
        let text = op["text"].as_str().unwrap_or("");
        if banned || !plain(text,256) {
            replies.push("IRC: бан или недопустимый текст".into()); continue;
        }
        let claim = sqlx::query_scalar::<_,i64>(
            "INSERT INTO social_profiles(user_id,last_message_at) VALUES($1,now()) ON CONFLICT(user_id) DO UPDATE SET last_message_at=now() WHERE NOT social_profiles.irc_banned AND (social_profiles.muted_until IS NULL OR social_profiles.muted_until <= now()) AND (social_profiles.last_message_at IS NULL OR social_profiles.last_message_at <= now()-interval '3 seconds') RETURNING user_id")
            .bind(uid).fetch_optional(&state.pool).await;
        match claim {
            Ok(Some(_)) => { accepted_chat=Some(text.to_string()); }
            Ok(None) => replies.push("IRC: мут, бан или задержка 3 секунды".into()),
            Err(_) => replies.push("IRC: ошибка базы данных".into()),
        }
        break;
    }
    let mut relay = match state.social.lock() { Ok(r) => r, Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"error":"relay"}))) };
    relay.prune();
    if req.leave { relay.peers.remove(&uid); return (StatusCode::OK, Json(json!({"ok":true,"cursor":relay.sequence}))); }
    if relay.peers.get(&uid).is_some_and(|p| p.last_sync.elapsed() < Duration::from_millis(150)) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"ok":false,"error":"rate limit"})));
    }
    if !relay.peers.contains_key(&uid) && relay.peers.len() >= 5000 {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"error":"capacity"})));
    }
    // Active account-to-avatar association is unique, but remains a client report.
    if !req.presence.game_uuid.is_empty() && relay.peers.iter().any(|(id,p)| *id!=uid && p.presence.game_uuid==req.presence.game_uuid && p.presence.room==req.presence.room) {
        return (StatusCode::CONFLICT, Json(json!({"ok":false,"error":"avatar already active"})));
    }
    let now = Instant::now();
    let peer = relay.peers.entry(uid).or_insert_with(|| Peer { presence:Presence::default(),username:username.clone(),seen:now,last_sync:now,last_throw:None });
    peer.presence = req.presence.clone(); peer.username = username.clone(); peer.seen = now; peer.last_sync = now;
    if let Some(text) = accepted_chat {
        relay.emit(None,String::new(),"chat",json!({"user_id":uid,"username":username,"role":role_label(&role),"prefix":prefix,"text":text}));
    }
    for op in &req.operations {
        match op["type"].as_str().unwrap_or("") {
            "throw" if req.presence.snow && !req.presence.room.is_empty() => {
                let id = op["projectile"].as_str().unwrap_or("");
                let (Some(position),Some(velocity)) = (vector(op.get("position")),vector(op.get("velocity"))) else { continue; };
                if !uuid(id) || relay.projectiles.contains_key(id) || distance(position,req.presence.position)>4.0
                    || distance(velocity,[0.0;3])>2.0 || relay.projectiles.len()>=2048
                    || relay.peers[&uid].last_throw.is_some_and(|t| t.elapsed()<Duration::from_secs(3)) { continue; }
                relay.peers.get_mut(&uid).unwrap().last_throw=Some(now);
                relay.projectiles.insert(id.into(),Projectile { owner:uid,room:req.presence.room.clone(),dimension:req.presence.dimension.clone(),start:position,velocity,created:now });
                relay.emit(Some(req.presence.room.clone()),req.presence.dimension.clone(),"throw",
                    json!({"projectile":id,"thrower":req.presence.game_uuid,"position":position,"velocity":velocity}));
            }
            "impact" if req.presence.snow => {
                let id = op["projectile"].as_str().unwrap_or("");
                let Some(projectile) = relay.projectiles.get(id) else { continue; };
                if projectile.owner!=uid || projectile.room!=req.presence.room || projectile.dimension!=req.presence.dimension { continue; }
                let Some(position) = vector(op.get("position")) else { continue; };
                // Validate against the projectile's ballistic path, allowing polling/network latency.
                let steps = ((projectile.created.elapsed().as_secs_f64()+1.0)*20.0).min(160.0) as usize;
                let mut p=projectile.start; let mut v=projectile.velocity; let mut nearest=f64::MAX;
                for _ in 0..=steps { nearest=nearest.min(distance(p,position)); for i in 0..3 {p[i]+=v[i];v[i]*=0.985;} v[1]-=0.015; }
                if nearest>1.5 { continue; }
                let victim=op["victim"].as_str().unwrap_or("");
                if !victim.is_empty() && !relay.peers.values().any(|p| p.presence.snow && p.presence.game_uuid==victim
                    && p.presence.room==req.presence.room && p.presence.dimension==req.presence.dimension
                    && distance([p.presence.position[0],p.presence.position[1]+0.9,p.presence.position[2]],position)<2.4) { continue; }
                relay.projectiles.remove(id);
                relay.emit(Some(req.presence.room.clone()),req.presence.dimension.clone(),"impact",json!({"projectile":id,"thrower":req.presence.game_uuid,"victim":victim,"position":position,"freezeTicks":60}));
            }
            _=>{}
        }
    }
    let events:Vec<Value>=relay.events.iter().filter(|e| e.id>req.cursor && match &e.room {
        None=>req.presence.irc && !banned,
        Some(room)=>req.presence.snow && room==&req.presence.room && e.dimension==req.presence.dimension,
    }).take(128).map(|e|json!({"id":e.id,"type":e.kind,"data":e.data})).collect();
    let cursor=if events.len()==128 { events.last().and_then(|e|e["id"].as_u64()).unwrap_or(relay.sequence) } else {relay.sequence};
    let peers:Vec<Value>=relay.peers.iter().filter(|(id,p)| **id!=uid && p.presence.room==req.presence.room && p.presence.dimension==req.presence.dimension)
        .take(256).map(|(id,p)|json!({"user_id":id,"username":p.username,"game_uuid":p.presence.game_uuid,
            "game_name":p.presence.game_name,"equipped":p.presence.equipped})).collect();
    (StatusCode::OK,Json(json!({"ok":true,"cursor":cursor,"peers":peers,"events":events,"replies":replies})))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn rejects_format_injection() { assert!(!plain("admin§c",24));assert!(!plain("hello\nadmin",256));assert!(plain("Здарова барни",256)); }
    #[test] fn validates_cosmetics_and_ids() { assert!(cosmetic_allowed(25));assert!(!cosmetic_allowed(26));assert!(!cosmetic_allowed(999));assert!(uuid("12345678-1234-1234-1234-123456789abc"));assert!(!uuid("x")); }
    #[test] fn role_is_not_free_text() {assert_eq!(role_label("Administrator"),"User");assert_eq!(role_label("admin"),"Administrator");assert_eq!(role_label("media"),"Media");}
    #[test] fn prefixes_cannot_impersonate_staff() {
        for role in ["user","media"] {
            for text in ["Developer","a_d-m i n","Owner","ModerAtor","§cDeveloper","Dеveloper"] {
                assert!(!prefix_allowed(text,role),"{role}: {text}");
            }
            assert!(prefix_allowed("Hello World",role));
            assert!(prefix_allowed("",role));
        }
        assert!(!prefix_allowed("Media","user"));
        assert!(prefix_allowed("Media","media"));
    }
    #[test] fn management_permissions_use_account_identity() {
        assert!(can_manage(1,"user",1,"prefix"));
        assert!(!can_manage(1,"media",2,"prefix"));
        assert!(!can_manage(1,"user",1,"mute"));
        assert!(!can_manage(1,"media",2,"ban"));
        assert!(!can_manage(1,"user",1,"unban"));
        assert!(can_manage(1,"admin",2,"ban"));
        assert!(can_manage(1,"admin",2,"unban"));
        assert!(can_manage(1,"admin",2,"mute"));
        assert!(!can_manage(1,"Administrator",2,"mute"));
    }
    #[test] fn moderation_targets_accept_uid_or_name() {
        assert_eq!(target_uid("42"),Some(42));
        assert_eq!(target_uid("uid:42"),Some(42));
        assert_eq!(target_uid("#42"),Some(42));
        assert_eq!(target_uid("NeVasilek"),None);
        assert_eq!(target_uid("-1"),None);
        assert_eq!(target_uid("9223372036854775808"),None);
    }
}
