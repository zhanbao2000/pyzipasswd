import _lzma
import os
import shutil
import string
import time
import zlib
from typing import Optional, Union, AnyStr

import py7zr
import pyzipper
from func_timeout import func_timeout, FunctionTimedOut

from unrar import rarfile, unrarlib

error_code_hint = {
    None: '无密码',
    AnyStr: '按字典破解成功，并且这个状态值(str)就是其解压密码',
    1: '不支持的文件类型',
    2: '字典中没有该压缩文件的密码',
    3: '是支持的文件类型，但压缩文件已损坏',
}

password_required_exceptions = (RuntimeError, py7zr.exceptions.PasswordRequired,)
password_invalid_exceptions = (RuntimeError, zlib.error, unrarlib.BadPassword, _lzma.LZMAError,)
temp_dir = os.path.join(os.getenv('TEMP'), 'pyzipasswd')
default_timeout = 3


def printc(text: str, fmt: str) -> None:
    # fmt: https://www.cnblogs.com/daofaziran/p/9015284.html
    print(f'\033[{fmt}m{text}\033[0m')


def str_width(mystr: str) -> int:
    """返回字符串的宽度"""
    count_en = count_dg = count_sp = count_al = count_pu = 0

    for s in mystr:
        if s in string.ascii_letters:  # 英文
            count_en += 1
        elif s.isdigit():  # 数字
            count_dg += 1
        elif s.isspace():  # 空格
            count_sp += 1
        elif s.isalpha():  # 全角字符
            count_al += 1
        else:  # 特殊字符
            count_pu += 1

    return count_en + count_dg + count_sp + count_al * 2 + count_pu


def add_passwd(new_passwd: str) -> None:
    """为字典添加新的密码"""
    fdict = open('dictionary.txt', 'r+', encoding='utf-8')
    passwd_list = [line.strip() for line in fdict]

    if new_passwd in passwd_list:
        print(f'密码 {new_passwd} 已存在于字典中，无需重复添加')
    else:
        passwd_list.append(new_passwd)
        print(f'密码 {new_passwd} 已添加至字典')

    fdict.seek(0)
    fdict.truncate()  # 清空文件

    passwd_list = sorted(passwd_list, key=lambda x: str_width(x))  # 按密码长度排序，美观
    count_now = len(passwd_list)
    for line in passwd_list:
        fdict.writelines(f'{line}\n')

    fdict.close()
    print(f'你的字典现在有 {count_now} 个密码')


def add_dict(passwd_dict_path: str) -> None:
    """将一个外部字典扩充到内部字典"""
    fdict = open('dictionary.txt', 'r+', encoding='utf-8')
    passwd_list = [line.strip() for line in fdict]
    count_old = len(passwd_list)
    fadd = open(passwd_dict_path, 'r+', encoding='utf-8')
    add_passwd_list = [line.strip() for line in fadd]
    conut_add = len(add_passwd_list)
    print(f'内部字典有 {count_old} 个密码，外部字典有 {conut_add} 个密码')

    fdict.seek(0)
    fdict.truncate()  # 清空文件

    passwd_list.extend(add_passwd_list)
    passwd_list = sorted(set(passwd_list), key=lambda x: str_width(x))  # 按密码长度排序并去重
    count_now = len(passwd_list)
    for line in passwd_list:
        fdict.writelines(f'{line}\n')

    fdict.close()
    fadd.close()

    print('从外部字典中添加了 {} 个密码到内部字典中，跳过了 {} 个已重复的密码'.format(
        count_now - count_old,
        conut_add - (count_now - count_old)
    ))
    print(f'你的字典现在有 {count_now} 个密码')


class Archive:
    def __init__(self, path: str):
        self.path = path  # C:/path/to/test.zip
        self.basename: str = os.path.basename(path)  # test.zip
        self.dirname: str = os.path.dirname(path)  # C:/path/to
        self.filename: str = os.path.splitext(self.basename)[0]  # test
        self.extension: str = os.path.splitext(self.basename)[1]  # .zip
        self.filesize: float = round(os.path.getsize(path) / (1024 * 1024), 2)  # MB
        self.filetime: str = time.asctime(time.localtime(os.path.getmtime(path)))
        self.target: Optional[str] = None

    def print_meta(self):
        """输出文件元数据"""
        print(f'文件名：{self.basename}\n'
              f'路径：{self.path}\n'
              f'大小：{self.filesize} MB\n'
              f'修改时间：{self.filetime}')


class Color:
    OK = '42;30'  # 绿底黑字
    noPasswd = '41;30'  # 红底黑字
    badFile = '45;30'  # 紫底黑字
    passwdFind = '46;30'  # 青底黑字
    tryDict = '43;30'  # 黄底黑字


class BadArchive(RuntimeError):
    """损坏的压缩文件"""


def handle_file(path: str, **kwargs) -> Optional[Union[str, int]]:
    """处理指定路径的压缩文件"""
    archive = Archive(path)
    archive.print_meta()

    # archive.target = kwargs.get('target', archive.dirname)  # 如果没有指定解压路径，那么解压到当前目录下
    # if kwargs.get('single', False):  # 如果指定了single=True，那么解压这个压缩文件到独立的目录（即按自身文件名建立的独立目录）
    #     archive.target = os.path.join(archive.target, archive.filename)
    archive.target = os.path.join(temp_dir, archive.filename)

    new_passwd: Optional[str] = kwargs.get('new_passwd', None)

    try:
        result = func_timeout(default_timeout, extract_direct, args=(archive,))
        if result == 1:
            print(f'不支持的文件类型：{archive.extension}\n{archive.basename} 已跳过')
        else:
            printc(f'{archive.basename} 无密码', Color.OK)
    except password_required_exceptions:
        printc('该压缩文件已加密，尝试字典破解', Color.tryDict)
        result = extract_dict(archive, new_passwd)
        if result == 2:
            print(f'\n\033[{Color.noPasswd}m尝试了字典中的所有密码，没有任何密码适用于该压缩文件，文件 {archive.basename} 测试失败\033[0m')
        else:
            print(f'\033[{Color.OK}m文件 {archive.basename} 已被字典破解\033[0m')
    except BadArchive:
        printc(f'文件 {archive.basename} 已损坏', Color.badFile)
        result = 3
    except FunctionTimedOut:
        printc(f'{archive.basename} 无密码', Color.OK)
        result = None

    return result


def handle_dir(dir_path: str, **kwargs):
    """处理指定目录内的压缩文件"""
    if not os.path.isdir(dir_path):
        print(f'{dir_path} 不是文件夹')
        return

    file_list = list(filter(
        lambda x: os.path.isfile(x),
        [os.path.join(dir_path, x) for x in os.listdir(dir_path)]
    ))  # 筛选出文件列表
    result: list[tuple[str, Union[str, int, None]]] = []  # 用于保存结果
    sum_all = len(file_list)  # 总数
    sum_ok = 0  # 测试成功（无密码或被破解）
    sum_other = 0  # 不支持的文件类型
    sum_no_passwd = 0  # 字典中没有该压缩文件的密码
    sum_bad_file = 0  # 是支持的文件类型，但压缩文件已损坏

    for index, file in enumerate(file_list, start=1):
        print(f'\n({index} / {sum_all})')
        result.append((
            os.path.basename(file),
            handle_file(path=file, **kwargs)
        ))

    print('\n\n测试结果')
    print(f'\033[{Color.OK}m  \033[0m：无密码或被破解')
    print(f'\033[{Color.noPasswd}m  \033[0m：字典中找不到解压密码')
    print(f'\033[{Color.badFile}m  \033[0m：损坏的文件')

    print('++++++++++++++++')
    for file, status in result:
        if status is None:
            printc(file, Color.OK)
            sum_ok += 1
        elif status == 1:
            print(file)
            sum_other += 1
        elif status == 2:
            printc(file, Color.noPasswd)
            sum_no_passwd += 1
        elif status == 3:
            printc(file, Color.badFile)
            sum_bad_file += 1
        elif isinstance(status, str):
            print(f'\033[{Color.OK}m{file}\033[0m -> {status}')
            sum_ok += 1
    print('++++++++++++++++')

    print(f'总数：{sum_all}，成功：{sum_ok}\n无关文件：{sum_other}，找不到密码：{sum_no_passwd}，文件损坏：{sum_bad_file}')


def extract_direct(archive: Archive) -> Union[str, int, None]:
    """直接破解一个压缩文件"""
    try:
        return pyzipper.ZipFile(archive.path).extractall(path=archive.target)
    except pyzipper.zipfile.BadZipFile:
        ...
    try:
        return rarfile.RarFile(archive.path).extractall(path=archive.target)
    except rarfile.BadRarFile:
        ...
    try:
        return py7zr.SevenZipFile(archive.path).extractall(path=archive.target)
    except py7zr.exceptions.Bad7zFile:
        ...
    raise BadArchive


def extract_dict(archive: Archive, new_passwd: Optional[str] = None) -> Union[str, int]:
    """利用字典破解一个加密的压缩文件"""
    def try_passwd(_test_passwd):
        try:
            pyzipper.AESZipFile(archive.path).extractall(path=archive.target, pwd=bytes(_test_passwd, encoding='utf-8'))
        except pyzipper.zipfile.BadZipFile:
            ...
        try:
            rarfile.RarFile(archive.path, pwd=_test_passwd).extractall(path=archive.target, pwd=_test_passwd)
        except rarfile.BadRarFile:
            ...
        try:
            py7zr.SevenZipFile(archive.path, password=_test_passwd).extractall(path=archive.target)
        except py7zr.exceptions.Bad7zFile:
            ...
        raise BadArchive

    if new_passwd is not None:
        add_passwd(new_passwd)

    with open('dictionary.txt', encoding='utf-8') as fdict:
        passwd_list = [line.strip() for line in fdict]
    count_now = len(passwd_list)
    for index, test_passwd in enumerate(passwd_list, start=1):
        try:
            print(f'\r({index}/{count_now}) 正在尝试：{test_passwd}', end='')
            func_timeout(default_timeout, try_passwd, args=(test_passwd,))
            print(f'\n\033[{Color.passwdFind}m在字典中发现了该压缩文件的密码：{test_passwd}\033[0m')
            return test_passwd
        except password_invalid_exceptions:
            continue
        except FunctionTimedOut:
            print(f'\n\033[{Color.passwdFind}m在字典中发现了该压缩文件的密码：{test_passwd}\033[0m')
            return test_passwd
        except UnicodeEncodeError:
            ...  # TODO rarfile bug ⑨
    return 2


def main():
    handle_dir(r"F:/path/to/dir")  # 批量测试文件夹内的压缩文件
    handle_file(r"F:/path/to/file/test.zip")  # 测试单个压缩文件
    add_passwd('new_password')  # 为内置字典添加新的密码
    add_dict(r'F:/path/to/new/dict.txt')  # 为内置字典一次性添加多个密码（一行一个）
    try:
        shutil.rmtree(temp_dir)
    except FileNotFoundError:
        pass


if __name__ == '__main__':
    main()
