import argparse
from scanner import Scanner

def main():
    parser = argparse.ArgumentParser(description="LinuxAntiVirusEngine: Linux ELF Malware Scanner")
    parser.add_argument("command", choices=["scan", "quarantine", "update", "config"])
    parser.add_argument("path", help="File or directory to scan")
    args = parser.parse_args()

    scanner = Scanner()
    if args.command == "scan":
        scanner.scan(args.path)
    # 其他命令...

if __name__ == "__main__":
    main()