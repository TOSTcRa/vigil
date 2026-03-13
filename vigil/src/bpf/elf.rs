// minimal ELF64 parser - only what we need to load BPF programs
// handles: section headers, symbol table, string tables, relocations

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_REL: u32 = 9;

pub struct ElfFile<'a> {
    data: &'a [u8],
    pub sections: Vec<Section<'a>>,
    pub symbols: Vec<Symbol>,
}

pub struct Section<'a> {
    pub name: String,
    pub sh_type: u32,
    pub data: &'a [u8],
    pub sh_info: u32,  // for REL sections: index of section being relocated
    pub sh_link: u32,  // for REL/SYMTAB: index of associated string/symbol table
    pub idx: usize,
}

pub struct Symbol {
    pub name: String,
    pub section_idx: u16,
    pub value: u64,
}

pub struct Relocation {
    pub offset: u64,
    pub sym_idx: u32,
}

impl<'a> ElfFile<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, String> {
        if data.len() < 64 {
            return Err("ELF too small".into());
        }

        // verify magic
        if data[0..4] != ELF_MAGIC {
            return Err("not an ELF file".into());
        }

        // verify ELF64 little-endian
        if data[4] != 2 {
            return Err("not ELF64".into());
        }
        if data[5] != 1 {
            return Err("not little-endian".into());
        }

        // read ELF header fields
        let e_shoff = u64_at(data, 40) as usize;     // section header table offset
        let e_shentsize = u16_at(data, 58) as usize;  // section header entry size
        let e_shnum = u16_at(data, 60) as usize;      // number of section headers
        let e_shstrndx = u16_at(data, 62) as usize;   // section name string table index

        if e_shoff == 0 || e_shnum == 0 {
            return Err("no section headers".into());
        }

        // first pass: read raw section headers
        let mut raw_sections: Vec<RawSectionHeader> = Vec::with_capacity(e_shnum);
        for i in 0..e_shnum {
            let off = e_shoff + i * e_shentsize;
            if off + e_shentsize > data.len() {
                return Err(format!("section header {} out of bounds", i));
            }
            raw_sections.push(RawSectionHeader {
                sh_name: u32_at(data, off),
                sh_type: u32_at(data, off + 4),
                sh_offset: u64_at(data, off + 24) as usize,
                sh_size: u64_at(data, off + 32) as usize,
                sh_link: u32_at(data, off + 40),
                sh_info: u32_at(data, off + 44),
            });
        }

        // get section name string table
        let shstrtab = &raw_sections[e_shstrndx];
        let shstrtab_data = &data[shstrtab.sh_offset..shstrtab.sh_offset + shstrtab.sh_size];

        // build sections with names
        let mut sections = Vec::with_capacity(e_shnum);
        for (i, raw) in raw_sections.iter().enumerate() {
            let name = read_str(shstrtab_data, raw.sh_name as usize);
            let sec_data = if raw.sh_size > 0 && raw.sh_offset + raw.sh_size <= data.len() {
                &data[raw.sh_offset..raw.sh_offset + raw.sh_size]
            } else {
                &[]
            };
            sections.push(Section {
                name,
                sh_type: raw.sh_type,
                data: sec_data,
                sh_info: raw.sh_info,
                sh_link: raw.sh_link,
                idx: i,
            });
        }

        // find symbol table and its string table
        let mut symbols = Vec::new();
        for sec in &sections {
            if sec.sh_type == SHT_SYMTAB {
                let strtab_idx = sec.sh_link as usize;
                let strtab_data = sections[strtab_idx].data;
                let entry_size = 24; // sizeof(Elf64_Sym)
                let count = sec.data.len() / entry_size;

                for i in 0..count {
                    let off = i * entry_size;
                    let st_name = u32_at(sec.data, off) as usize;
                    let st_info = sec.data[off + 4];
                    let st_shndx = u16_at(sec.data, off + 6);
                    let st_value = u64_at(sec.data, off + 8);

                    let _ = st_info; // we don't filter by binding/type

                    symbols.push(Symbol {
                        name: read_str(strtab_data, st_name),
                        section_idx: st_shndx,
                        value: st_value,
                    });
                }
                break; // only one SYMTAB
            }
        }

        Ok(ElfFile {
            data,
            sections,
            symbols,
        })
    }

    // returns (section, attach_point) for BPF program sections
    // e.g. "tracepoint/syscalls/sys_enter_ptrace" -> (section, "syscalls/sys_enter_ptrace")
    // e.g. "kprobe/do_init_module" -> (section, "do_init_module")
    pub fn program_sections(&self) -> Vec<(&Section<'a>, &str)> {
        let mut result = Vec::new();
        for sec in &self.sections {
            if sec.sh_type != SHT_PROGBITS || sec.data.is_empty() {
                continue;
            }
            if sec.name.starts_with("tracepoint/") {
                let attach = &sec.name["tracepoint/".len()..];
                result.push((sec, attach));
            } else if sec.name.starts_with("kprobe/") {
                let attach = &sec.name["kprobe/".len()..];
                result.push((sec, attach));
            }
        }
        result
    }

    // get relocations for a given section index
    pub fn relocations_for(&self, section_idx: usize) -> Vec<Relocation> {
        let mut result = Vec::new();
        for sec in &self.sections {
            if sec.sh_type == SHT_REL && sec.sh_info as usize == section_idx {
                let entry_size = 16; // sizeof(Elf64_Rel)
                let count = sec.data.len() / entry_size;
                for i in 0..count {
                    let off = i * entry_size;
                    let r_offset = u64_at(sec.data, off);
                    let r_info = u64_at(sec.data, off + 8);
                    let sym_idx = (r_info >> 32) as u32;
                    result.push(Relocation {
                        offset: r_offset,
                        sym_idx,
                    });
                }
            }
        }
        result
    }

    // find section by name
    pub fn section_by_name(&self, name: &str) -> Option<&Section<'a>> {
        self.sections.iter().find(|s| s.name == name)
    }
}

struct RawSectionHeader {
    sh_name: u32,
    sh_type: u32,
    sh_offset: usize,
    sh_size: usize,
    sh_link: u32,
    sh_info: u32,
}

// read a null-terminated string from a string table
fn read_str(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - offset);
    String::from_utf8_lossy(&data[offset..offset + end]).into_owned()
}

fn u16_at(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn u32_at(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn u64_at(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off],
        data[off + 1],
        data[off + 2],
        data[off + 3],
        data[off + 4],
        data[off + 5],
        data[off + 6],
        data[off + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_too_small() {
        let data = [0u8; 32];
        assert!(ElfFile::parse(&data).is_err());
    }

    #[test]
    fn reject_bad_magic() {
        let mut data = [0u8; 128];
        data[0] = 0x00; // not 0x7f
        assert!(ElfFile::parse(&data).is_err());
    }

    #[test]
    fn reject_not_elf64() {
        let mut data = [0u8; 128];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 1; // ELF32, not ELF64
        assert!(ElfFile::parse(&data).is_err());
    }

    #[test]
    fn reject_big_endian() {
        let mut data = [0u8; 128];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2; // ELF64
        data[5] = 2; // big-endian
        assert!(ElfFile::parse(&data).is_err());
    }

    #[test]
    fn u16_at_works() {
        let data = [0x34, 0x12];
        assert_eq!(u16_at(&data, 0), 0x1234);
    }

    #[test]
    fn u32_at_works() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(u32_at(&data, 0), 0x12345678);
    }

    #[test]
    fn u64_at_works() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(u64_at(&data, 0), 0x0807060504030201);
    }

    #[test]
    fn read_str_basic() {
        let data = b"hello\0world\0";
        assert_eq!(read_str(data, 0), "hello");
        assert_eq!(read_str(data, 6), "world");
    }

    #[test]
    fn read_str_out_of_bounds() {
        let data = b"test\0";
        assert_eq!(read_str(data, 100), "");
    }

    #[test]
    fn read_str_empty_at_null() {
        let data = b"\0abc";
        assert_eq!(read_str(data, 0), "");
    }
}
