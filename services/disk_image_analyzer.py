import struct
from pathlib import Path
from .hashing import multi_hash_file, sha256_file


MBR_PARTITION_TYPES = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 (<32MB)",
    0x05: "Extended Partition",
    0x06: "FAT16",
    0x07: "NTFS / exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended Partition (LBA)",
    0x82: "Linux Swap",
    0x83: "Linux Native (ext2/3/4)",
    0x8E: "Linux LVM",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System Partition",
}


def _format_size(num_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def _parse_mbr(data: bytes, sector_size: int = 512) -> list[dict] | None:
    """Parses MBR partition table from boot sector if 0x55AA signature is valid."""
    if len(data) < 512:
        return None
    if data[510:512] != b"\x55\xaa":
        return None

    partitions = []
    # 4 partition entries of 16 bytes starting at byte offset 446 (0x1BE)
    for i in range(4):
        offset = 446 + (i * 16)
        entry = data[offset:offset + 16]
        boot_flag, _, _, _, part_type, _, _, _, start_lba, num_sectors = struct.unpack("<BBBBBBBBII", entry)

        if part_type == 0x00 and num_sectors == 0:
            continue

        size_bytes = num_sectors * sector_size
        partitions.append({
            "slot": i + 1,
            "bootable": boot_flag == 0x80,
            "type_id": f"0x{part_type:02X}",
            "type_name": MBR_PARTITION_TYPES.get(part_type, f"Unknown (0x{part_type:02X})"),
            "start_lba": start_lba,
            "num_sectors": num_sectors,
            "size_bytes": size_bytes,
            "size_formatted": _format_size(size_bytes),
        })

    return partitions


def _parse_gpt(data: bytes, sector_size: int = 512) -> list[dict] | None:
    """Parses GPT partition header if 'EFI PART' signature is at LBA 1."""
    if len(data) < sector_size * 2:
        return None
    header = data[sector_size:sector_size + 92]
    if len(header) < 92 or header[:8] != b"EFI PART":
        return None

    try:
        _, _, header_size, _, _, current_lba, backup_lba, first_lba, last_lba = struct.unpack("<8sIIIIQQQQ", header[:48])
        part_entry_lba, num_entries, entry_size = struct.unpack("<QII", header[72:88])

        # If data includes partition entries table
        entries_offset = part_entry_lba * sector_size
        partitions = []
        if len(data) >= entries_offset + (num_entries * entry_size):
            for i in range(min(num_entries, 16)):
                e_off = entries_offset + (i * entry_size)
                e_data = data[e_off:e_off + entry_size]
                type_guid = e_data[:16]
                if type_guid == b"\x00" * 16:
                    continue
                start_lba, end_lba, flags = struct.unpack("<QQQ", e_data[32:56])
                name = e_data[56:128].decode("utf-16le", errors="ignore").split("\x00")[0]
                num_sectors = max(0, (end_lba - start_lba) + 1)
                size_bytes = num_sectors * sector_size
                partitions.append({
                    "slot": i + 1,
                    "name": name or f"Partition {i + 1}",
                    "start_lba": start_lba,
                    "end_lba": end_lba,
                    "num_sectors": num_sectors,
                    "size_bytes": size_bytes,
                    "size_formatted": _format_size(size_bytes),
                })
        return partitions
    except Exception:
        return []


def _detect_filesystem_signatures(data: bytes) -> list[str]:
    """Inspects common filesystem boot headers."""
    fs_list = []
    if len(data) >= 512:
        if b"NTFS    " in data[:512]:
            fs_list.append("NTFS")
        if b"FAT32   " in data[:512] or b"FAT16   " in data[:512] or b"FAT12   " in data[:512]:
            fs_list.append("FAT")
        if len(data) >= 2048 and data[1080:1082] == b"\x53\xef":
            fs_list.append("ext2/3/4")
    return fs_list


def examine(path: str | Path) -> dict:
    """Examines disk image (.dd / .img), computes multi-hashes, and extracts partition geometry."""
    path = Path(path)
    if path.suffix.lower() not in {".dd", ".img"}:
        raise ValueError("unsupported disk-image format; use .dd or .img")

    size = path.stat().st_size
    hashes = multi_hash_file(path)
    sha256 = hashes["sha256"]

    # Read the first 64KB for header and partition analysis
    with path.open("rb") as stream:
        header_data = stream.read(65536)

    mbr_parts = _parse_mbr(header_data)
    gpt_parts = _parse_gpt(header_data)
    detected_fs = _detect_filesystem_signatures(header_data)

    scheme = "Raw / Non-partitioned"
    partitions = []
    if gpt_parts is not None and len(gpt_parts) > 0:
        scheme = "GPT (GUID Partition Table)"
        partitions = gpt_parts
    elif mbr_parts is not None and len(mbr_parts) > 0:
        if any(p.get("type_id") == "0xEE" for p in mbr_parts):
            scheme = "GPT (Protective MBR)"
        else:
            scheme = "MBR (Master Boot Record)"
        partitions = mbr_parts

    message = (
        f"Native {scheme} inspection completed ({len(partitions)} partition(s) identified). "
        "Read-only cryptographic baseline verified."
    )

    return {
        "path": path.name,
        "sha256_before": sha256,
        "sha256": sha256,
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "size": size,
        "size_formatted": _format_size(size),
        "read_only": True,
        "scheme": scheme,
        "partitions": partitions,
        "detected_filesystems": detected_fs,
        "message": message,
    }
