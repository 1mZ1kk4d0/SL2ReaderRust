use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::str;
use std::collections::HashMap;

use utils::decryptor::decrypt_file;
use utils::utils::{format_time, Character};

mod utils;


const PROFILE: phf::Map<&'static str, ProfileData> = phf::phf_map! {
    
    "er" => ProfileData {
        is_encrypted: false,
        character_name_max_length: 16,
        character_slots_count: 10,
        file_index: 10,
        slot_data_offset: 6494,
        slot_length: 588,
        slots_occupancy_offset: 6484,
    },
    "ds3" => ProfileData {
        is_encrypted: true,
        character_name_max_length: 16,
        character_slots_count: 10,
        file_index: 10,
        slot_data_offset: 4254,
        slot_length: 554,
        slots_occupancy_offset: 4244,
    },
};

struct ProfileData {
    is_encrypted: bool,
    character_name_max_length: usize,
    character_slots_count: usize,
    file_index: usize,
    slot_data_offset: usize,
    slot_length: usize,
    slots_occupancy_offset: usize,
}

struct BND4Entry {
    profile: &'static str,
    raw: Vec<u8>,
    size: usize,
    char_entry_offset: usize,
    char_entry_size: usize,
    name: String,
    iv: Vec<u8>,
    entry_data: Vec<u8>,
    decrypted_data: Vec<u8>,
    checksum: Vec<u8>,
    char_entry_data_offset: usize,
    char_entry_name_offset: usize,
}

impl BND4Entry {
    fn new(raw: Vec<u8>, profile_key: &'static str) -> Self {
        let profile_data = &PROFILE[profile_key];

        let size = raw.len();
        let entry_header_offset = 64;
        let entry_header_length = 32;

        let char_entry_offset = entry_header_offset + entry_header_length * profile_data.file_index;
        let char_entry_size = read_u32_le(&raw, char_entry_offset + 8) as usize;
        let char_entry_data_offset = read_u32_le(&raw, char_entry_offset + 16) as usize;
        let char_entry_name_offset = read_u32_le(&raw, char_entry_offset + 20) as usize;

        let name = read_null_terminated_utf16le_string(&raw, char_entry_name_offset);
        let iv = raw[char_entry_data_offset..char_entry_data_offset + 16].to_vec();
        let entry_data = raw[char_entry_data_offset + 16..char_entry_data_offset + char_entry_size].to_vec();

        let decrypted_data = if profile_data.is_encrypted {
            decrypt_file(&entry_data, &iv)
        } else {
            Vec::new()
        };
        

        let checksum = raw[char_entry_offset..char_entry_offset + 16].to_vec();

        BND4Entry {
            profile: profile_key,
            raw,
            size,
            char_entry_offset,
            char_entry_size,
            name,
            iv,
            entry_data,
            decrypted_data,
            checksum,
            char_entry_data_offset,
            char_entry_name_offset,
        }
    }

    fn get_characters(&self) -> Vec<Character> {
        let mut chars = Vec::new();
        let current_profile = &PROFILE[self.profile];

        if self.profile == "ds3" {
            let name_section_size = current_profile.character_name_max_length * 2 + 2;
            let checksum_with_padding_size = 16 + 4;
            let level_size = 4;

            for i in 0..current_profile.character_slots_count {
                let offset_name = current_profile.slot_data_offset + checksum_with_padding_size + i * current_profile.slot_length;
                let offset_level = current_profile.slot_data_offset + checksum_with_padding_size + name_section_size + i * current_profile.slot_length;
                let offset3_timestamp = current_profile.slot_data_offset + checksum_with_padding_size + name_section_size + level_size + i * current_profile.slot_length;
                let slot_unoccupied = self.decrypted_data[current_profile.slots_occupancy_offset + checksum_with_padding_size + i] == 0;

                if !slot_unoccupied {
                    chars.push(Character {
                        character_slot: (i + 1) as u32,
                        character_name: read_null_terminated_utf16le_string(&self.decrypted_data, offset_name),
                        character_level: read_int(&self.decrypted_data, offset_level),
                        character_time: read_int(&self.decrypted_data, offset3_timestamp),
                        character_time_format: format_time(read_int(&self.decrypted_data, offset3_timestamp)),
                    });
                }
            }
        }

        if self.profile == "er" {
            let name_section_size = current_profile.character_name_max_length * 2 + 2;
            let level_size = 4;

            for i in 0..current_profile.character_slots_count {
                let offset_name = current_profile.slot_data_offset + i * current_profile.slot_length;
                let offset_level = current_profile.slot_data_offset + name_section_size + i * current_profile.slot_length;
                let offset3_timestamp = current_profile.slot_data_offset + name_section_size + level_size + i * current_profile.slot_length;
                let slot_unoccupied = self.entry_data[current_profile.slots_occupancy_offset + i] == 0;

                if !slot_unoccupied {
                    chars.push(Character {
                        character_slot: (i + 1) as u32,
                        character_name: read_null_terminated_utf16le_string(&self.entry_data, offset_name),
                        character_level: read_int(&self.entry_data, offset_level),
                        character_time: read_int(&self.entry_data, offset3_timestamp),
                        character_time_format: format_time(read_int(&self.entry_data, offset3_timestamp)),
                    });
                }
            }
        }

        chars
    }
}

fn read_null_terminated_utf16le_string(buffer: &[u8], offset: usize) -> String {
    let mut end_offset = offset;
    while end_offset < buffer.len() {
        if read_u16_le(buffer, end_offset) == 0x0000 {
            break;
        }
        end_offset += 2;
    }

    if end_offset == offset {
        String::new() // Retorna uma string vazia se nenhum caractere foi encontrado
    } else {
        String::from_utf16_lossy(
            &buffer[offset..end_offset]
                .chunks(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<u16>>(),
        )
    }
}

fn read_u32_le(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]])
}

fn read_u16_le(buffer: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buffer[offset], buffer[offset + 1]])
}

fn read_int(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buffer[offset], buffer[offset + 1], buffer[offset + 2], buffer[offset + 3]])
}

fn load_sl2(file_path: &str, profile: &'static str) {

    println!("DEBUG: Iniciando load sl2");
    let raw = fs::read(file_path).expect("msg");
    println!("DEBUG: Carregando perfil {}", profile);
    let entry = BND4Entry::new(raw, profile);
    let characters = entry.get_characters();

    for character in characters {
        println!("{:?}", character);
    }

    
}

fn main() {
    let file_paths = [
        "A:\\Projetos\\GitHub\\DK3\\DecryptedFile2.txt", // Decrypted DS3
        "C:\\Users\\guilh\\AppData\\Roaming\\EldenRing\\76561199002602391\\ER0000.sl2",
        "C:\\Users\\guilh\\AppData\\Roaming\\DarkSoulsIII\\011000013e20cb97\\DS30000.sl2", // Encrypted DS3
    ];

    load_sl2(file_paths[1], "er");
        
    
}


