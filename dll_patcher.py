import os
import shutil
import subprocess
import sys

import pefile


def align(val, alignment):
    if alignment == 0:
        return val
    return ((val + alignment - 1) // alignment) * alignment


def check_tools():
    missing = []
    if not shutil.which("ffmpeg"):
        missing.append("ffmpeg")
    if not shutil.which("7z"):
        missing.append("7z")

    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}")
        return False
    return True


def extract_dll(dll_path, output_dir):
    print(f"Extracting {dll_path}...")
    try:
        # -y: assume Yes on all queries
        # -o{output_dir}: set output directory
        subprocess.check_call(
            ["7z", "x", dll_path, f"-o{output_dir}", "-y"], stdout=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Extraction failed: {e}")
        return False


def convert_audio(resources_dir):
    print("Converting audio files to mp3...")
    # Look for .rsrc/DATA/AUDIO/SFX
    # Or just search recursively for .WMA

    wma_files = []
    for root, dirs, files in os.walk(resources_dir):
        for file in files:
            if file.upper().endswith(".WMA"):
                wma_files.append(os.path.join(root, file))

    print(f"Found {len(wma_files)} WMA files.")

    for fpath in wma_files:
        tmp_path = fpath + ".tmp.wma"
        try:
            # ffmpeg -i input -ar 44100 output -y
            # -v error: quiet output
            subprocess.check_call(
                [
                    "ffmpeg",
                    "-i",
                    fpath,
                    "-c:a",
                    "libmp3lame",
                    tmp_path,
                    "-y",
                    "-v",
                    "error",
                ]
            )
            os.replace(tmp_path, fpath)
        except subprocess.CalledProcessError as e:
            print(f"Failed to convert {fpath}: {e}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


def patch_pe(dll_path, resources_dir, output_path):
    print("Patching PE structure...")

    try:
        pe = pefile.PE(dll_path)
    except Exception as e:
        print(f"Failed to load PE: {e}")
        return False

    # 1. Load Replacement Data from resources_dir
    # We look for files in .rsrc/DATA/AUDIO/SFX inside resources_dir
    # But 7z structure might vary? Assuming standard structure.
    # The extracted structure is typically .rsrc/DATA/...

    # We need to map: "AUDIO\SFX\FILENAME.WMA" -> content
    replacements = {}

    # Walk and match
    data_dir = os.path.join(resources_dir, ".rsrc", "DATA")
    if not os.path.isdir(data_dir):
        # Maybe it extracted directly?
        data_dir = os.path.join(resources_dir, "DATA")

    if not os.path.isdir(data_dir):
        print(f"Could not find DATA directory in {resources_dir}")
        return False

    for root, dirs, files in os.walk(data_dir):
        for filename in files:
            if filename.upper().endswith(".WMA"):
                # Construct resource name
                # Extracted path: .../DATA/AUDIO/SFX/FILE.WMA
                # Resource name: AUDIO\SFX\FILE.WMA

                abs_path = os.path.join(root, filename)
                rel_path = os.path.relpath(abs_path, data_dir)

                # Convert path separators to backslash
                resource_name = rel_path.replace(os.path.sep, "\\")

                # Check if it looks like a resource we want (SFX)
                if resource_name.startswith("AUDIO\\SFX\\"):
                    with open(abs_path, "rb") as f:
                        replacements[resource_name] = f.read()

    if not replacements:
        print("No WMA replacements found.")
        return False

    print(f"Loaded {len(replacements)} audio resources.")

    # 2. Prepare Data Blob
    new_data_blob = bytearray()
    new_data_map = {}  # filename -> (offset, size)

    current_offset = 0
    for name, data in replacements.items():
        new_data_map[name] = (current_offset, len(data))
        new_data_blob.extend(data)
        current_offset += len(data)

    data_len = len(new_data_blob)
    print(f"New data size: {data_len} bytes")

    # 3. Locate .rsrc section
    rsrc_section = pe.sections[-1]
    # Check if last section is indeed .rsrc or something we can append to
    # Usually .rsrc is last.

    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

    old_raw_size = rsrc_section.SizeOfRawData
    old_raw_ptr = rsrc_section.PointerToRawData
    old_va = rsrc_section.VirtualAddress

    append_start_rva = old_va + old_raw_size

    # 4. Update Section Headers
    new_raw_size = align(old_raw_size + data_len, file_alignment)
    # We update VirtualSize to cover the new data
    new_virt_size = old_raw_size + data_len

    rsrc_section.SizeOfRawData = new_raw_size
    rsrc_section.Misc_VirtualSize = new_virt_size

    # Update SizeOfImage
    new_image_size = align(old_va + new_raw_size, section_alignment)
    pe.OPTIONAL_HEADER.SizeOfImage = new_image_size

    print(f"Section expanded: {hex(old_raw_size)} -> {hex(new_raw_size)}")

    # 5. Update Resource Directory
    updated_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(resource_type, "directory"):
                for resource_entry in resource_type.directory.entries:
                    res_name = str(resource_entry.name) if resource_entry.name else None
                    if res_name and res_name in new_data_map:
                        offset, size = new_data_map[res_name]
                        new_rva = append_start_rva + offset

                        if hasattr(resource_entry, "directory"):
                            for lang_entry in resource_entry.directory.entries:
                                if hasattr(lang_entry, "data"):
                                    lang_entry.data.struct.OffsetToData = new_rva
                                    lang_entry.data.struct.Size = size
                                    updated_count += 1

    print(f"Updated pointers for {updated_count} resources.")

    # 6. Write
    pe.write(output_path)

    # 7. Append Data
    with open(output_path, "r+b") as f:
        f.seek(0, 2)
        current_file_size = f.tell()

        expected_start = old_raw_ptr + old_raw_size

        if current_file_size != expected_start:
            # Pad or Seek
            if current_file_size < expected_start:
                f.write(b"\x00" * (expected_start - current_file_size))
            else:
                f.seek(expected_start)

        f.write(new_data_blob)

        # Final padding
        final_pos = f.tell()
        aligned_end = old_raw_ptr + new_raw_size
        if final_pos < aligned_end:
            f.write(b"\x00" * (aligned_end - final_pos))

    return True


def main():
    if len(sys.argv) < 3:
        print("Usage: dll_patcher.py <input_dll> <output_dll>")
        sys.exit(1)

    input_dll = sys.argv[1]
    output_dll = sys.argv[2]

    if not os.path.exists(input_dll):
        print(f"Input file not found: {input_dll}")
        sys.exit(1)

    if not check_tools():
        sys.exit(1)

    # Temp dir for extraction
    tmp_dir = "dll_extract_tmp"
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    os.makedirs(tmp_dir)

    try:
        if not extract_dll(input_dll, tmp_dir):
            sys.exit(1)

        convert_audio(tmp_dir)

        if not patch_pe(input_dll, tmp_dir, output_dll):
            sys.exit(1)

        print(f"Successfully created {output_dll}")

    finally:
        # Cleanup temp
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)


if __name__ == "__main__":
    main()
