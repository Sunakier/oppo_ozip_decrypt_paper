#!/usr/bin/env python3
# (c) B. Kerler 2017-2020, licensed under MIT license
"""
Usage:
    ozipdecrypt.py --help
    ozipdecrypt.py <filename>

Options:
    Mode 1 for regular ozip, Mode 2 for CPH1803/CPH1909 [default: 1]
"""

import os
import sys
import stat
import shutil
import binascii
import glob
from Crypto.Cipher import AES
import zipfile


# AES keys for various OPPO devices
KEYS = [
    "D6EECF0AE5ACD4E0E9FE522DE7CE381E",  # mnkey
    "D6ECCF0AE5ACD4E0E92E522DE7C1381E",  # mkey
    # realkey, R9s CPH1607 MSM8953, Plus, R11, RMX1921 Realme XT, RMX1851EX Realme Android 10, RMX1992EX_11_OTA_1050
    "D6DCCF0AD5ACD4E0292E522DB7C1381E",
    "D7DCCE1AD4AFDCE2393E5161CBDC4321",  # testkey
    "D7DBCE2AD4ADDCE1393E5521CBDC4321",  # utilkey
    "D7DBCE1AD4AFDCE1393E5121CBDC4321",  # R11s CPH1719 MSM8976, Plus
    "D4D2CD61D4AFDCE13B5E01221BD14D20",  # FindX CPH1871 SDM845
    "261CC7131D7C1481294E532DB752381E",  # FindX
    "1CA21E12271335AE33AB81B2A7B14622",  # Realme 2 pro SDM660/MSM8976
    "D4D2CE11D4AFDCE13B3E0121CBD14D20",  # K1 SDM660/MSM8976
    # Realme 3 Pro SDM710, X, 5 Pro, Q, RMX1921 Realme XT
    "1C4C1EA3A12531AE491B21BB31613C11",
    # Reno 10x zoom PCCM00 SDM855, CPH1921EX Reno 5G
    "1C4C1EA3A12531AE4A1B21BB31C13C21",
    "1C4A11A3A12513AE441B23BB31513121",  # Reno 2 PCKM00 SDM730G
    "1C4A11A3A12589AE441A23BB31517733",  # Realme X2 SDM730G
    "1C4A11A3A22513AE541B53BB31513121",  # Realme 5 SDM665
    "2442CE821A4F352E33AE81B22BC1462E",  # R17 Pro SDM710
    "14C2CD6214CFDC2733AE81B22BC1462C",  # CPH1803 OppoA3s SDM450/MSM8953
    "1E38C1B72D522E29E0D4ACD50ACFDCD6",
    "12341EAAC4C123CE193556A1BBCC232D",
    "2143DCCB21513E39E1DCAFD41ACEDBD7",
    "2D23CCBBA1563519CE23C1C4AA1E3412",  # A77 CPH1715 MT6750T
    "172B3E14E46F3CE13E2B5121CBDC4321",  # Realme 1 MTK P60
    "ACAA1E12A71431CE4A1B21BBA1C1C6A2",  # Realme U1 RMX1831 MTK P70
    "ACAC1E13A72531AE4A1B22BB31C1CC22",  # Realme 3 RMX1825EX P70
    "1C4411A3A12533AE441B21BB31613C11",  # A1k CPH1923 MTK P22
    # Reno 3 PCRM00 MTK 1000L, CPH2059 OPPO A92, CPH2067 OPPO A72
    "1C4416A8A42717AE441523B336513121",
    "55EEAA33112133AE441B23BB31513121",  # RenoAce SDM855Plus
    "ACAC1E13A12531AE4A1B21BB31C13C21",  # Reno, K3
    "ACAC1E13A72431AE4A1B22BBA1C1C6A2",  # A9
    "12CAC11211AAC3AEA2658690122C1E81",  # A1,A83t
    "1CA21E12271435AE331B81BBA7C14612",  # CPH1909 OppoA5s MT6765
    "D1DACF24351CE428A9CE32ED87323216",  # Realme1(reserved)
    "A1CC75115CAECB890E4A563CA1AC67C8",  # A73(reserved)
    "2132321EA2CA86621A11241ABA512722",  # Realme3(reserved)
    "22A21E821743E5EE33AE81B227B1462E"
    # F3 Plus CPH1613 - MSM8976
]


def keytest(data):
    """Test encryption keys against data to find the correct one."""
    for key in KEYS:
        ctx = AES.new(binascii.unhexlify(key), AES.MODE_ECB)
        dat = ctx.decrypt(data)
        if (dat[0:4] == b'\x50\x4B\x03\x04'):
            print(f"✅ 找到正确的 AES 密钥: {key}")
            return binascii.unhexlify(key)
        elif (dat[0:4] == b'\x41\x56\x42\x30'):
            print(f"✅ 找到正确的 AES 密钥: {key}")
            return binascii.unhexlify(key)
        elif (dat[0:4] == b'\x41\x4E\x44\x52'):
            print(f"✅ 找到正确的 AES 密钥: {key}")
            return binascii.unhexlify(key)
    return -1


def del_rw(action, name, exc):
    """Change file permissions and remove file."""
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


def rmrf(path):
    """Recursively remove file or directory."""
    if os.path.exists(path):
        if os.path.isfile(path):
            del_rw("", path, "")
        else:
            shutil.rmtree(path, onerror=del_rw)


def decryptfile(key, rfilename):
    """Decrypt a file using AES ECB mode (Mode 1)."""
    with open(rfilename, 'rb') as rr:
        with open(rfilename+".tmp", 'wb') as wf:
            rr.seek(0x10)
            dsize = int(rr.read(0x10).replace(
                b"\x00", b"").decode('utf-8'), 10)
            rr.seek(0x1050)
            flen = os.stat(rfilename).st_size - 0x1050

            ctx = AES.new(key, AES.MODE_ECB)
            while (dsize > 0):
                if flen > 0x4000:
                    size = 0x4000
                else:
                    size = flen
                data = rr.read(size)
                if dsize < size:
                    size = dsize
                if len(data) == 0:
                    break
                dr = ctx.decrypt(data)
                wf.write(dr[:size])
                flen -= size
                dsize -= size
    os.remove(rfilename)
    os.rename(rfilename+".tmp", rfilename)


def decryptfile2(key, rfilename, wfilename):
    """Decrypt a file using AES ECB mode with block structure (Mode 2)."""
    with open(rfilename, 'rb') as rr:
        with open(wfilename, 'wb') as wf:
            ctx = AES.new(key, AES.MODE_ECB)
            bstart = 0
            goon = True
            while (goon):
                rr.seek(bstart)
                header = rr.read(12)
                if len(header) == 0:
                    break
                if header != b"OPPOENCRYPT!":
                    return 1
                rr.seek(0x10 + bstart)
                bdsize = int(rr.read(0x10).replace(
                    b"\x00", b"").decode('utf-8'), 10)
                if bdsize < 0x40000:
                    goon = False
                rr.seek(0x50 + bstart)
                while (bdsize > 0):
                    data = rr.read(0x10)
                    if len(data) == 0:
                        break
                    size = 0x10
                    if bdsize < 0x10:
                        size = bdsize
                    dr = ctx.decrypt(data)
                    wf.write(dr[:size])
                    bdsize -= 0x10
                    data = rr.read(0x3FF0)
                    if len(data) == 0:
                        break
                    bdsize -= 0x3FF0
                    wf.write(data)
                bstart = bstart + 0x40000 + 0x50
    return 0


def mode2(filename):
    """Process Mode 2 encrypted OZIP files (CPH1803/CPH1909)."""
    temp = os.path.join(os.path.abspath(os.path.dirname(filename)), "temp")
    out = os.path.join(os.path.abspath(os.path.dirname(filename)), "out")

    with open(filename, 'rb') as fr:
        magic = fr.read(12)
        if magic[:2] == b"PK":
            with zipfile.ZipFile(filename, 'r') as zipObj:
                if os.path.exists(temp):
                    rmrf(temp)
                os.mkdir(temp)
                if os.path.exists(out):
                    rmrf(out)
                os.mkdir(out)

                print("🔍 正在查找密钥...  " + filename)
                key = None  # 初始化 key 变量

                for zi in zipObj.infolist():
                    orgfilename = zi.filename
                    if "boot.img" in orgfilename:
                        zi.filename = "out"
                        zipObj.extract(zi, temp)
                        zi.filename = orgfilename
                        with open(os.path.join(temp, "out"), 'rb') as rr:
                            magic = rr.read(12)
                            if magic == b"OPPOENCRYPT!":
                                rr.seek(0x50)
                                data = rr.read(16)
                                key = keytest(data)
                                if key == -1:
                                    print(
                                        "❌ 未知的 AES 密钥,请先从 recovery 中提取密钥!")
                                    return 1
                                else:
                                    break
                            else:
                                print(
                                    "⚠️  未知的模式2,boot.img 未被加密")
                                break

                # 检查是否找到密钥
                if key is None or key == -1:
                    print("❌ 未能找到有效的解密密钥!")
                    rmrf(temp)
                    return 1

                print("📦 正在提取文件...  " + filename)
                outzip = filename[:-4] + 'zip'
                if os.path.exists(outzip):
                    os.remove(outzip)
                with zipfile.ZipFile(outzip, 'w', zipfile.ZIP_DEFLATED) as WzipObj:
                    for zi in zipObj.infolist():
                        orgfilename = zi.filename
                        zi.filename = "out"
                        zipObj.extract(zi, temp)
                        zi.filename = orgfilename
                        with open(os.path.join(temp, "out"), 'rb') as rr:
                            magic = rr.read(12)
                            if magic == b"OPPOENCRYPT!":
                                print("🔓 正在解密 " + orgfilename)
                                if decryptfile2(key, os.path.join(temp, "out"), os.path.join(temp, "out")+".dec") == 1:
                                    return 1
                                WzipObj.write(os.path.join(
                                    temp, "out")+".dec", orgfilename)
                                rr.close()
                                os.remove(os.path.join(temp, "out"))
                                os.remove(os.path.join(temp, "out")+".dec")
                            else:
                                WzipObj.write(os.path.join(
                                    temp, "out"), orgfilename)
                                rr.close()
                                os.remove(os.path.join(temp, "out"))
                rmrf(temp)
                print("✅ 完成! 文件已解密到: " + outzip)
                return 0
    return 1


def find_ozip_files(directory="."):
    """在指定目录下查找所有 .ozip 文件"""
    pattern = os.path.join(directory, "*.ozip")
    files = glob.glob(pattern)
    return sorted([os.path.basename(f) for f in files])


def display_file_menu(files):
    """显示文件选择菜单"""
    print("\n" + "="*60)
    print("  OPPO OZIP 解密工具 v1.32")
    print("  OPPO OZIP Decryption Tool")
    print("  Rewrite By LazyerPaper")
    print("="*60)

    if not files:
        print("\n❌ 当前目录下未找到 .ozip 文件")
        print("   请将 .ozip 文件放置在当前目录下,或使用以下方式:")
        print("   1. 拖拽 .ozip 文件到本程序")
        print("   2. 使用命令: python ozipdecrypt.py <文件路径>")
        return None

    print(f"\n📁 在当前目录找到 {len(files)} 个 .ozip 文件:\n")

    for idx, filename in enumerate(files, 1):
        file_size = os.path.getsize(filename)
        size_mb = file_size / (1024 * 1024)
        print(f"  [{idx}] {filename} ({size_mb:.2f} MB)")

    print(f"\n  [0] 手动输入文件路径")
    print(f"  [q] 退出程序")

    while True:
        try:
            choice = input("\n👉 请选择要解密的文件编号: ").strip().lower()

            if choice == 'q':
                print("\n👋 程序已退出")
                return None

            if choice == '0':
                file_path = input("📝 请输入文件路径 (支持拖放): ").strip()
                # 移除可能的引号
                file_path = file_path.strip('"').strip("'")
                if os.path.exists(file_path):
                    return file_path
                else:
                    print(f"❌ 文件不存在: {file_path}")
                    continue

            idx = int(choice)
            if 1 <= idx <= len(files):
                return files[idx - 1]
            else:
                print(f"❌ 请输入 0-{len(files)} 之间的数字或 'q' 退出")
        except ValueError:
            print("❌ 输入无效,请输入数字或 'q'")
        except KeyboardInterrupt:
            print("\n\n👋 程序已退出")
            return None


def main(file_arg):
    """Main function to decrypt OZIP files."""
    print("\n🔓 开始解密 OZIP 文件...")
    print(f"📄 文件: {file_arg}\n")
    filename = file_arg

    try:
        with open(filename, 'rb') as fr:
            magic = fr.read(12)
            if magic == b"OPPOENCRYPT!":
                pk = False
            elif magic[:2] == b"PK":
                pk = True
            else:
                print("❌ ozip 文件格式未知,需要 OPPOENCRYPT! 标识!")
                return 1

            if pk == False:
                fr.seek(0x1050)
                data = fr.read(16)
                key = keytest(data)
                if (key == -1):
                    print("❌ 未知的 AES 密钥,请先从 recovery 中提取密钥!")
                    return 1
                ctx = AES.new(key, AES.MODE_ECB)
                filename = file_arg[:-4] + "zip"
                with open(filename, 'wb') as wf:
                    fr.seek(0x1050)
                    print("🔓 正在解密...")
                    while True:
                        data = fr.read(16)
                        if len(data) == 0:
                            break
                        wf.write(ctx.decrypt(data))
                        data = fr.read(0x4000)
                        if len(data) == 0:
                            break
                        wf.write(data)
                print("✅ 完成!!")
                print(f"📁 输出文件: {filename}")
            else:
                testkey = True
                filename = os.path.abspath(file_arg)
                path = os.path.abspath(os.path.dirname(filename))
                outpath = os.path.join(path, "tmp")

                try:
                    if os.path.exists(outpath):
                        shutil.rmtree(outpath)
                    os.mkdir(outpath)

                    with zipfile.ZipFile(filename, 'r') as zo:
                        clist = []
                        key = None  # 初始化 key 变量

                        try:
                            if zo.extract('oppo_metadata', outpath):
                                with open(os.path.join(outpath, 'oppo_metadata')) as rt:
                                    for line in rt:
                                        clist.append(line[:-1])
                        except Exception as e:
                            print("❌ 模式1 检测失败", str(e))
                            print("🔄 检测到模式 2....")
                            return mode2(filename)

                        if testkey:
                            fname = ''
                            if "firmware-update/vbmeta.img" in clist:
                                fname = "firmware-update/vbmeta.img"
                            elif "vbmeta.img" in clist:
                                fname = 'vbmeta.img'
                            if fname != '':
                                if zo.extract(fname, outpath):
                                    fname_path = os.path.join(
                                        outpath, fname.replace("/", os.sep))
                                    with open(fname_path, "rb") as rt:
                                        rt.seek(0x1050)
                                        data = rt.read(16)
                                        key = keytest(data)
                                        if (key == -1):
                                            print(
                                                "❌ 未知的 AES 密钥,请先从 recovery 中提取密钥!")
                                            return 1
                                    testkey = False
                            if testkey == True:
                                print(
                                    "⚠️  未知的镜像,请报告问题并提供镜像名称!")
                                return 1

                        # 检查是否成功获取密钥
                        if key is None or key == -1:
                            print("❌ 未能获取有效的解密密钥!")
                            rmrf(outpath)
                            return 1

                        outzip = filename[:-4] + 'zip'
                        with zipfile.ZipFile(outzip, 'w', zipfile.ZIP_DEFLATED) as WzipObj:
                            for info in zo.infolist():
                                print("📦 正在提取 " + info.filename)
                                orgfilename = info.filename
                                info.filename = "out"
                                zo.extract(info, outpath)
                                info.filename = orgfilename
                                if len(clist) > 0:
                                    if info.filename in clist:
                                        print("🔓 正在解密 " + info.filename)
                                        decryptfile(
                                            key, os.path.join(outpath, "out"))
                                else:
                                    with open(os.path.join(outpath, "out"), 'rb') as rr:
                                        magic = rr.read(12)
                                        if magic == b"OPPOENCRYPT!":
                                            decryptfile(
                                                key, os.path.join(outpath, "out"))
                                WzipObj.write(os.path.join(
                                    outpath, "out"), orgfilename)
                        rmrf(os.path.join(outpath, "out"))
                        rmrf(outpath)
                        print("✅ 完成! 文件已解密到: " + outzip)
                        return 0
                except Exception as e:
                    # Clean up temporary directory on error
                    if os.path.exists(outpath):
                        rmrf(outpath)
                    raise
    except FileNotFoundError:
        print(f"\n❌ 错误: 文件 '{file_arg}' 不存在!")
        return 1
    except PermissionError:
        print(f"\n❌ 错误: 无法访问 '{file_arg}', 权限被拒绝!")
        return 1
    except Exception as e:
        print(f"\n❌ 错误: {str(e)}")
        return 1


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description="OPPO OZIP 解密工具 v1.32 (c) B.Kerler 2017-2022 Rewrite By LazyerPaper", add_help=False)
    optional = parser.add_argument_group('可选参数')
    optional.add_argument("filename", nargs='?', help="OZIP 文件路径 (可选)")
    optional.add_argument("-h", "--help", action="help",
                          help="显示帮助信息并退出")
    args = parser.parse_args()

    # 如果没有提供文件参数,显示交互式菜单
    if args.filename is None:
        ozip_files = find_ozip_files()
        selected_file = display_file_menu(ozip_files)

        if selected_file is None:
            sys.exit(0)

        exit_code = main(selected_file)
    else:
        # 移除可能的引号 (支持拖放)
        file_path = args.filename.strip('"').strip("'")
        exit_code = main(file_path)

    # 等待用户按键后退出 (方便查看输出)
    print("\n" + "="*60)
    input("💡 按回车键退出...")
    sys.exit(exit_code)
