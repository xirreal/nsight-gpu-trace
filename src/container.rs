use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::{Error, Result};

pub const WRPV_MAGIC: [u8; 4] = *b"WRPV";
pub const SUPPORTED_VERSION: u32 = 10;
const SECTION_MAGIC: u16 = 0x1234;
const CHUNK_MAGIC: u16 = 0x4321;
const FILE_HEADER_SIZE: u64 = 8;
const SECTION_HEADER_SIZE: u64 = 24;
const CHUNK_HEADER_SIZE: u64 = 24;
const MAX_SECTIONS: usize = 4096;
const MAX_CHUNKS: u32 = 1_000_000;
const MAX_CHUNK_UNPACKED: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionRole {
    ProtobufTrace,
    CounterData,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Chunk {
    pub index: u32,
    pub header_offset: u64,
    pub payload_offset: u64,
    pub compression: u16,
    pub reserved: u32,
    pub stored_size: u64,
    pub unpacked_size: u64,
}

impl Chunk {
    pub fn compression_name(&self) -> &'static str {
        match self.compression {
            0 => "none",
            1 => "lz4_block",
            _ => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Section {
    pub index: usize,
    pub header_offset: u64,
    pub flag_a: u16,
    pub flag_b: u16,
    pub reserved_06: u16,
    pub reserved_0c: u32,
    pub unpacked_size: u64,
    pub chunks: Vec<Chunk>,
}

impl Section {
    pub fn role(&self) -> SectionRole {
        match (self.flag_a, self.flag_b) {
            (1, 0) => SectionRole::ProtobufTrace,
            (0, 1) => SectionRole::CounterData,
            _ => SectionRole::Unknown,
        }
    }

    pub fn stored_size(&self) -> u64 {
        self.chunks.iter().map(|chunk| chunk.stored_size).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Container {
    pub path: PathBuf,
    pub version: u32,
    pub file_size: u64,
    pub sections: Vec<Section>,
}

impl Container {
    /// Parse and validate the complete outer WRPV container.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let file_size = file.metadata()?.len();
        if file_size < FILE_HEADER_SIZE {
            return Err(Error::InvalidCapture(
                "file is too short for a WRPV header".into(),
            ));
        }
        let mut reader = BufReader::new(file);
        let magic = read_array::<4>(&mut reader, "file magic")?;
        if magic != WRPV_MAGIC {
            return Err(Error::InvalidCapture(format!(
                "bad file magic {magic:?}; expected {WRPV_MAGIC:?}"
            )));
        }
        let version = read_u32(&mut reader, "container version")?;
        if version != SUPPORTED_VERSION {
            return Err(Error::InvalidCapture(format!(
                "unsupported WRPV version {version}; only version {SUPPORTED_VERSION} is validated"
            )));
        }

        let mut sections = Vec::new();
        while reader.stream_position()? < file_size {
            if sections.len() >= MAX_SECTIONS {
                return Err(Error::InvalidCapture("implausible section count".into()));
            }
            let header_offset = reader.stream_position()?;
            ensure_remaining(
                file_size,
                header_offset,
                SECTION_HEADER_SIZE,
                "section header",
            )?;
            let magic = read_u16(&mut reader, "section magic")?;
            let flag_a = read_u16(&mut reader, "section flag A")?;
            let flag_b = read_u16(&mut reader, "section flag B")?;
            let reserved_06 = read_u16(&mut reader, "section reserved field")?;
            let chunk_count = read_u32(&mut reader, "chunk count")?;
            let reserved_0c = read_u32(&mut reader, "section reserved field")?;
            let unpacked_size = read_u64(&mut reader, "section unpacked size")?;
            if magic != SECTION_MAGIC {
                return Err(Error::InvalidCapture(format!(
                    "bad section magic {magic:#x} at {header_offset:#x}"
                )));
            }
            if chunk_count > MAX_CHUNKS {
                return Err(Error::InvalidCapture(format!(
                    "implausible chunk count {chunk_count}"
                )));
            }

            let mut chunks = Vec::with_capacity(chunk_count as usize);
            let mut actual_unpacked = 0u64;
            for index in 0..chunk_count {
                let chunk_offset = reader.stream_position()?;
                ensure_remaining(file_size, chunk_offset, CHUNK_HEADER_SIZE, "chunk header")?;
                let magic = read_u16(&mut reader, "chunk magic")?;
                let compression = read_u16(&mut reader, "chunk compression")?;
                let reserved = read_u32(&mut reader, "chunk reserved field")?;
                let stored_size = read_u64(&mut reader, "chunk stored size")?;
                let chunk_unpacked = read_u64(&mut reader, "chunk unpacked size")?;
                if magic != CHUNK_MAGIC {
                    return Err(Error::InvalidCapture(format!(
                        "bad chunk magic {magic:#x} at {chunk_offset:#x}"
                    )));
                }
                if chunk_unpacked > MAX_CHUNK_UNPACKED {
                    return Err(Error::InvalidCapture(format!(
                        "chunk {index} requests {chunk_unpacked} unpacked bytes; limit is {MAX_CHUNK_UNPACKED}"
                    )));
                }
                let payload_offset = reader.stream_position()?;
                ensure_remaining(file_size, payload_offset, stored_size, "chunk payload")?;
                actual_unpacked = actual_unpacked.checked_add(chunk_unpacked).ok_or_else(|| {
                    Error::InvalidCapture("section unpacked size overflow".into())
                })?;
                chunks.push(Chunk {
                    index,
                    header_offset: chunk_offset,
                    payload_offset,
                    compression,
                    reserved,
                    stored_size,
                    unpacked_size: chunk_unpacked,
                });
                reader.seek(SeekFrom::Current(i64::try_from(stored_size).map_err(
                    |_| Error::InvalidCapture("chunk stored size cannot be represented".into()),
                )?))?;
            }
            if actual_unpacked != unpacked_size {
                return Err(Error::InvalidCapture(format!(
                    "section {} declares {unpacked_size} unpacked bytes, chunks sum to {actual_unpacked}",
                    sections.len()
                )));
            }
            sections.push(Section {
                index: sections.len(),
                header_offset,
                flag_a,
                flag_b,
                reserved_06,
                reserved_0c,
                unpacked_size,
                chunks,
            });
        }

        Ok(Self {
            path,
            version,
            file_size,
            sections,
        })
    }

    pub fn section(&self, role: SectionRole) -> Result<&Section> {
        let mut matches = self
            .sections
            .iter()
            .filter(|section| section.role() == role);
        let first = matches
            .next()
            .ok_or_else(|| Error::InvalidCapture(format!("capture has no {role:?} section")))?;
        if matches.next().is_some() {
            return Err(Error::InvalidCapture(format!(
                "capture has multiple {role:?} sections"
            )));
        }
        Ok(first)
    }

    pub fn read_chunk(&self, chunk: &Chunk) -> Result<Vec<u8>> {
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(chunk.payload_offset))?;
        let stored_len = usize::try_from(chunk.stored_size)
            .map_err(|_| Error::InvalidCapture("chunk is too large for this platform".into()))?;
        let mut stored = vec![0; stored_len];
        file.read_exact(&mut stored)?;
        match chunk.compression {
            0 if chunk.stored_size == chunk.unpacked_size => Ok(stored),
            0 => Err(Error::InvalidCapture(
                "stored chunk has different stored and unpacked sizes".into(),
            )),
            1 => lz4_flex::block::decompress(
                &stored,
                usize::try_from(chunk.unpacked_size).map_err(|_| {
                    Error::InvalidCapture("unpacked chunk is too large for this platform".into())
                })?,
            )
            .map_err(|error| Error::InvalidCapture(format!("LZ4 decompression failed: {error}"))),
            value => Err(Error::InvalidCapture(format!(
                "unknown chunk compression code {value}"
            ))),
        }
    }

    pub fn write_section(&self, section: &Section, output: &mut impl Write) -> Result<()> {
        let mut written = 0u64;
        for chunk in &section.chunks {
            let data = self.read_chunk(chunk)?;
            output.write_all(&data)?;
            written += data.len() as u64;
        }
        if written != section.unpacked_size {
            return Err(Error::InvalidCapture(format!(
                "materialized section has {written} bytes; expected {}",
                section.unpacked_size
            )));
        }
        Ok(())
    }

    pub fn read_section(&self, section: &Section) -> Result<Vec<u8>> {
        let capacity = usize::try_from(section.unpacked_size)
            .map_err(|_| Error::InvalidCapture("section is too large for this platform".into()))?;
        let mut data = Vec::with_capacity(capacity);
        self.write_section(section, &mut data)?;
        Ok(data)
    }
}

fn ensure_remaining(file_size: u64, offset: u64, amount: u64, what: &str) -> Result<()> {
    let end = offset
        .checked_add(amount)
        .ok_or_else(|| Error::InvalidCapture(format!("{what} offset overflow")))?;
    if end > file_size {
        return Err(Error::InvalidCapture(format!(
            "truncated {what} at {offset:#x}: need {amount} bytes, file size is {file_size}"
        )));
    }
    Ok(())
}

fn read_array<const N: usize>(reader: &mut impl Read, what: &str) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| Error::InvalidCapture(format!("could not read {what}: {error}")))?;
    Ok(bytes)
}

fn read_u16(reader: &mut impl Read, what: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(read_array(reader, what)?))
}

fn read_u32(reader: &mut impl Read, what: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array(reader, what)?))
}

fn read_u64(reader: &mut impl Read, what: &str) -> Result<u64> {
    Ok(u64::from_le_bytes(read_array(reader, what)?))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    fn push_u16(data: &mut Vec<u8>, value: u16) {
        data.extend(value.to_le_bytes());
    }

    fn push_u32(data: &mut Vec<u8>, value: u32) {
        data.extend(value.to_le_bytes());
    }

    fn push_u64(data: &mut Vec<u8>, value: u64) {
        data.extend(value.to_le_bytes());
    }

    fn section(flags: (u16, u16), payloads: &[&[u8]]) -> Vec<u8> {
        let mut data = Vec::new();
        push_u16(&mut data, SECTION_MAGIC);
        push_u16(&mut data, flags.0);
        push_u16(&mut data, flags.1);
        push_u16(&mut data, 0);
        push_u32(&mut data, payloads.len() as u32);
        push_u32(&mut data, 0);
        push_u64(
            &mut data,
            payloads.iter().map(|item| item.len() as u64).sum(),
        );
        for payload in payloads {
            push_u16(&mut data, CHUNK_MAGIC);
            push_u16(&mut data, 0);
            push_u32(&mut data, 0);
            push_u64(&mut data, payload.len() as u64);
            push_u64(&mut data, payload.len() as u64);
            data.extend_from_slice(payload);
        }
        data
    }

    #[test]
    fn parses_and_reassembles_multiple_chunks() {
        let mut data = WRPV_MAGIC.to_vec();
        data.extend(SUPPORTED_VERSION.to_le_bytes());
        data.extend(section((1, 0), &[b"protobuf"]));
        data.extend(section((0, 1), &[b"LOP", b"DATA\0payload"]));
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&data).unwrap();

        let container = Container::open(file.path()).unwrap();
        assert_eq!(container.sections.len(), 2);
        let counters = container.section(SectionRole::CounterData).unwrap();
        assert_eq!(
            container.read_section(counters).unwrap(),
            b"LOPDATA\0payload"
        );
    }

    #[test]
    fn rejects_future_versions() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"WRPV\x0b\0\0\0").unwrap();
        let error = Container::open(file.path()).unwrap_err().to_string();
        assert!(error.contains("unsupported WRPV version 11"));
    }
}
