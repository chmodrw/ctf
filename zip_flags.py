#!/usr/bin/env python3
"""比较 ZIP 本地头与中央目录加密位；可验证并生成去除伪加密位的副本。"""
import argparse
import io
import struct
import zipfile
import zlib
from _common import read_limited, run, save


def inspect(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        rows = []
        for info in archive.infolist():
            offset = info.header_offset
            if data[offset:offset+4] != b'PK\x03\x04':
                raise ValueError('本地头签名错误')
            local = struct.unpack_from('<H', data, offset+6)[0]
            rows.append((info, local))
        return rows, archive.start_dir


def clear_fake(data, max_expanded=64*1024*1024):
    rows, central = inspect(data)
    if sum(info.file_size for info, _ in rows) > max_expanded:
        raise ValueError('解压验证总量超过上限')
    output = bytearray(data)
    for info, local in rows:
        if (info.flag_bits | local) & 0x40 or info.compress_type == 99:
            raise ValueError('强加密/AES 格式不适用伪加密清位')
        struct.pack_into('<H', output, info.header_offset+6, local & ~1)
        if output[central:central+4] != b'PK\x01\x02':
            raise ValueError('中央目录异常')
        flags = struct.unpack_from('<H', output, central+8)[0]
        struct.pack_into('<H', output, central+8, flags & ~1)
        names, extras, comments = struct.unpack_from('<HHH', output, central+28)
        central += 46+names+extras+comments
    # Prove content is actually readable and CRC-correct before publishing a copy.
    total = 0
    with zipfile.ZipFile(io.BytesIO(output)) as archive:
        for info in archive.infolist():
            with archive.open(info) as stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_expanded:
                        raise ValueError('实际解压数据超过上限')
    return bytes(output)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('file')
    p.add_argument('--clear-fake', action='store_true', help='清除 bit0 后逐项解压并检查 CRC；全部通过才写出')
    p.add_argument('-o', '--output')
    a = p.parse_args()
    data = read_limited(a.file, 64*1024*1024)
    try:
        rows, _ = inspect(data)
        for info, local in rows:
            print('%r method=%d size=%d local_flags=0x%04x central_flags=0x%04x encrypted=%s mismatch=%s' %
                  (info.filename, info.compress_type, info.file_size, local, info.flag_bits, bool(info.flag_bits & 1), local != info.flag_bits))
        if a.clear_fake:
            if not a.output:
                p.error('--clear-fake 需要 -o 新路径')
            value = clear_fake(data)
            save(a.output, value)
            print('所有成员解压及 CRC 校验通过。')
        elif a.output:
            p.error('-o 需要配合 --clear-fake')
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error) as exc:
        raise ValueError('无法验证为伪加密；可能是真加密或文件损坏：' + str(exc)) from exc


if __name__ == '__main__':
    run(main)

