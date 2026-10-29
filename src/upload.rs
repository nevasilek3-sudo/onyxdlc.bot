use sha2::{Digest, Sha256};

const MAX_BINARY: usize = 128 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct Parts {
    base: String,
    total: usize,
    next: usize,
    bytes: Vec<u8>,
}

// Chunks use <filename>.sha256-<full hash>.part1of2. Nothing is written to disk.
pub(super) fn accept(state: &mut Option<Parts>, filename: &str, bytes: Vec<u8>) -> Result<Option<Vec<u8>>, &'static str> {
    if bytes.is_empty() || bytes.len() > 20 * 1024 * 1024 { return Err("Часть должна быть от 1 байта до 20 МБ."); }
    let Some((base, suffix)) = filename.rsplit_once(".part") else {
        if state.is_some() { return Err("Сначала отправьте оставшиеся части или отмените загрузку."); }
        if !bytes.starts_with(b"MZ") { return Err("Нужен исходный DLL-файл, без ZIP или RAR."); }
        return Ok(Some(bytes));
    };
    let Some((part,total)) = suffix.split_once("of") else { return Err("Неверное имя части."); };
    let (Ok(part),Ok(total)) = (part.parse::<usize>(), total.parse::<usize>()) else { return Err("Неверный номер части."); };
    if !(2..=16).contains(&total) || !(1..=total).contains(&part) { return Err("Неверное число частей (от 2 до 16)."); }
    let Some((_,hash)) = base.rsplit_once(".sha256-") else { return Err("В имени частей нужен SHA256: файл.dll.sha256-<хеш>.part1of2"); };
    if hash.len()!=64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("Неверный SHA256 в имени файла."); }
    if state.is_none() {
        if part!=1 { return Err("Начните с первой части (part1of...)."); }
        if !bytes.starts_with(b"MZ") { return Err("Первая часть не содержит начало DLL."); }
        *state=Some(Parts {base:base.into(),total,next:1,bytes:Vec::new()});
    }
    let upload=state.as_mut().unwrap();
    if upload.base!=base || upload.total!=total || upload.next!=part { return Err("Отправьте следующую часть этого же файла по порядку."); }
    if upload.bytes.len()+bytes.len()>MAX_BINARY { return Err("Общий размер DLL не должен превышать 128 МБ."); }
    upload.bytes.extend(bytes);
    upload.next+=1;
    if part!=total { return Ok(None); }
    let completed=state.take().unwrap();
    if hex::encode(Sha256::digest(&completed.bytes))!=hash.to_ascii_lowercase() {
        return Err("SHA256 не совпал. Загрузите все части заново, начиная с первой.");
    }
    Ok(Some(completed.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn assembles_and_checks_order() {
        let data=b"MZ-test-payload";
        let base=format!("output.dll.sha256-{}",hex::encode(Sha256::digest(data)));
        let mut state=None;
        assert!(accept(&mut state,&format!("{base}.part2of2"),data[4..].to_vec()).is_err());
        assert!(accept(&mut state,&format!("{base}.part1of2"),data[..4].to_vec()).unwrap().is_none());
        assert!(accept(&mut state,&format!("{base}.part1of2"),data[..4].to_vec()).is_err());
        assert_eq!(accept(&mut state,&format!("{base}.part2of2"),data[4..].to_vec()).unwrap().unwrap(),data);
        assert!(state.is_none());
    }
    #[test] fn corrupt_or_mixed_parts_never_publish() {
        let mut state=None;
        let base=format!("output.dll.sha256-{}","a".repeat(64));
        assert!(accept(&mut state,&format!("{base}.part1of2"),b"MZaa".to_vec()).unwrap().is_none());
        assert!(accept(&mut state,&format!("other.{base}.part2of2"),b"bb".to_vec()).is_err());
        assert!(accept(&mut state,&format!("{base}.part2of2"),b"bb".to_vec()).is_err());
        assert!(state.is_none());
        assert!(accept(&mut state,"output.zip",b"PKzip".to_vec()).is_err());
    }
}
