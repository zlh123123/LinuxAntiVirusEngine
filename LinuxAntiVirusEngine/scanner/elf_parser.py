from elftools.elf.elffile import ELFFile
import math

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

def is_packed(file_path):
    try:
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)
            # 检查UPX签名（节区名称）
            for section in elf.iter_sections():
                if section.name.startswith('.upx'):
                    return True, "UPX加壳"
            # 检查熵（阈值调高到7.5）
            for section in elf.iter_sections():
                data = section.data()
                if data and calculate_entropy(data) > 7.5:
                    return True, f"高熵节区（{section.name}），可能是加壳"
            # 检查入口点是否在有效PT_LOAD段内
            entry = elf.header['e_entry']
            in_valid_segment = False
            for segment in elf.iter_segments():
                if segment.header['p_type'] == 'PT_LOAD':
                    start = segment.header['p_vaddr']
                    end = start + segment.header['p_memsz']
                    if start <= entry < end:
                        in_valid_segment = True
                        break
            if not in_valid_segment:
                return True, "入口点不在有效加载段，可能是加壳"
            # 检查节区数量（太少或太多可能异常）
            sections = list(elf.iter_sections())
            if len(sections) < 3 or len(sections) > 50:  # 启发式阈值
                return True, f"节区数量异常（{len(sections)}），可能是加壳"
        return False, "未检测到加壳"
    except Exception as e:
        return False, f"解析失败：{str(e)}"