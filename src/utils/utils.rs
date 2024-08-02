use std::fmt::Write;

pub fn format_time(seconds: u32) -> String {
    let hrs = seconds / 3600;
    let mins = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let format_number = |num: u32| -> String {
        format!("{:02}", num)
    };

    format!("{}:{}:{}", format_number(hrs), format_number(mins), format_number(secs))
}

pub fn find(buffer: &[u8]) -> isize {
    for i in 0..buffer.len() - 1 {
        if buffer[i] == 0x00 && buffer[i + 1] == 0x00 {
            return i as isize;
        }
    }
    -1 // Retorna -1 se a sequência não for encontrada
}

#[derive(Debug)]
pub struct Character {
    pub character_slot: u32,
    pub character_name: String,
    pub character_level: u32,
    pub character_time: u32,
    pub character_time_format: String,
}


