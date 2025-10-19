# filepath: /root/autodl-tmp/LinuxAntiVirusEngine/tests/test_elf_parser.py
import pytest
from LinuxAntiVirusEngine.scanner.elf_parser import is_packed
import os

def test_normal_elf():
    # 正常ELF文件
    result, reason = is_packed('/root/autodl-tmp/test')
    assert result == False
    assert "未检测到加壳" in reason

def test_packed_elf():
    # UPX加壳文件
    file_path = '/root/autodl-tmp/upx-5.0.2-amd64_linux/test_upx'
    if not os.path.exists(file_path):
        pytest.fail(f"文件不存在: {file_path}")  # 如果文件不存在，直接fail
    result, reason = is_packed(file_path)
    assert result == True, f"加壳检测失败: {reason}"  # 打印失败理由
    assert "UPX加壳" in reason or "高熵" in reason or "节区数量异常" in reason