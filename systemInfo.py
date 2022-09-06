# -*- coding: utf-8 -*-
"""
@name: 系统信息 / SystemInfo
@author: LQS
@time: 2020年8月17日
@version: 0.2
"""

from typing import List, Dict, Any
from prettytable import PrettyTable
import os
import time
import psutil
import platform
import hashlib
import re
import sys
import json


from cachelib import SimpleCache

cache = SimpleCache()


UNIX: bool = os.name == "posix"
SYS: str = platform.system()

# dbpasswd
with open("/etc/juminfo.conf", "r") as fp:
    dbpasswd = fp.read().strip()


class CpuConstants:
    def __init__(self):
        """
        初始化CPU常量（多平台）

        Returns
        -------
        self.

        """
        self.WMI = None
        self.initialed: bool = False
        self.cpuList: list = []  # windows only

        self.cpuCount: int = 0  # 物理cpu数量
        self.cpuCore: int = 0  # cpu物理核心数
        self.cpuThreads: int = 0  # cpu逻辑核心数
        self.cpuName: str = ""  # cpu型号

        self.Update(True)

    def Update(self, update: bool = False) -> None:
        """
        更新cpu数据

        Returns
        -------
        None.

        """
        if UNIX:
            self.GetCpuConstantsUnix(update)
        else:
            self.GetCpuConstantsWindows(update)

        self.initialed: bool = True

    @property
    def getDict(self) -> Dict[int, str]:
        """
        以字典格式获取当前cpu常量

        Returns
        -------
        Dict[int, str]
            DESCRIPTION.

        """
        if not self.initialed:
            self.Update()
        return {
            "cpu_count": self.cpuCount,
            "cpu_name": self.cpuName,
            "cpu_core": self.cpuCore,
            "cpu_threads": self.cpuThreads,
        }

    def GetCpuConstantsUnix(self, update: bool = False) -> None:
        """
        获取unix下的cpu信息

        Parameters
        ----------
        update : bool, optional
            DESCRIPTION. The default is False.

        Returns
        -------
        None
            DESCRIPTION.

        """
        if update or not self.initialed:
            ids: list = re.findall("physical id.+", readFile("/proc/cpuinfo"))

            # 物理cpu个数
            self.cpuCount: int = len(set(ids))

            # cpu型号（名称）
            self.cpuName: str = self.getCpuTypeUnix()

            self.GetCpuConstantsBoth()

    def InitWmi(self) -> None:
        """
        初始化wmi（for windows）

        Returns
        -------
        None
            DESCRIPTION.

        """
        import wmi

        self.WMI = wmi.WMI()

    def GetCpuConstantsBoth(self, update: bool = False) -> None:
        """
        获取多平台共用的cpu信息

        Parameters
        ----------
        update : bool, optional
            强制更新数据. The default is False.

        Returns
        -------
        None
            DESCRIPTION.

        """
        if update or not self.initialed:

            # cpu逻辑核心数
            self.cpuThreads: int = psutil.cpu_count()

            # cpu物理核心数
            self.cpuCore: int = psutil.cpu_count(logical=False)

    def GetCpuConstantsWindows(self, update: bool = False) -> None:
        """
        获取windows平台的cpu信息

        Parameters
        ----------
        update : bool, optional
            强制更新数据. The default is False.

        Returns
        -------
        None
            DESCRIPTION.

        """
        if update or not self.initialed:

            # 初始化wmi
            if self.WMI == None:
                self.InitWmi()

            # cpu列表
            self.cpuList: list = self.WMI.Win32_Processor()

            # 物理cpu个数
            self.cpuCount: int = len(self.cpuList)

            # cpu型号（名称）
            self.cpuName: str = self.cpuList[0].Name

            self.GetCpuConstantsBoth()

    @staticmethod
    def getCpuTypeUnix() -> str:
        """
        获取CPU型号（unix）

        Returns
        -------
        str
            CPU型号.

        """
        cpuinfo: str = readFile("/proc/cpuinfo")
        rep: str = "model\s+name\s+:\s+(.+)"
        tmp = re.search(rep, cpuinfo, re.I)
        cpuType: str = ""
        if tmp:
            cpuType: str = tmp.groups()[0]
        else:
            cpuinfo = ExecShellUnix('LANG="en_US.UTF-8" && lscpu')[0]
            rep = "Model\s+name:\s+(.+)"
            tmp = re.search(rep, cpuinfo, re.I)
            if tmp:
                cpuType = tmp.groups()[0]
        return cpuType


def GetCpuInfo(interval: int = 1) -> Dict[str, Any]:
    """
    获取CPU信息

    Parameters
    ----------
    interval : int, optional
        DESCRIPTION. The default is 1.

    Returns
    -------
    Dict[float, list, dict]
        DESCRIPTION.

    """
    time.sleep(0.5)

    # cpu总使用率
    used: float = psutil.cpu_percent(interval)

    # 每个逻辑cpu使用率
    usedList: List[float] = psutil.cpu_percent(percpu=True)

    return {"used": used, "used_list": usedList, **cpuConstants.getDict}


def readFile(filename: str) -> str:
    """
    读取文件内容

    Parameters
    ----------
    filename : str
        文件名.

    Returns
    -------
    str
        文件内容.

    """
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return file.read()
    except:
        pass

    return ""


def GetLoadAverage() -> dict:
    """
    获取服务器负载状态（多平台）

    Returns
    -------
    dict
        DESCRIPTION.

    """
    try:
        c: list = os.getloadavg()
    except:
        c: list = [0, 0, 0]
    data: dict = {i: c[idx] for idx, i in enumerate(("one", "five", "fifteen"))}
    data["max"] = psutil.cpu_count() * 2
    data["limit"] = data["max"]
    data["safe"] = data["max"] * 0.75
    return data


def GetMemInfo() -> dict:
    """
    获取内存信息（多平台）

    Returns
    -------
    dict
        DESCRIPTION.

    """
    if UNIX:
        return GetMemInfoUnix()
    return GetMemInfoWindows()


def GetMemInfoUnix() -> Dict[str, int]:
    """
    获取内存信息（unix）

    Returns
    -------
    dict
        DESCRIPTION.

    """
    mem = psutil.virtual_memory()
    memInfo: dict = {
        "memTotal": ToSizeInt(mem.total, "MB"),
        "memFree": ToSizeInt(mem.free, "MB"),
        "memBuffers": ToSizeInt(mem.buffers, "MB"),
        "memCached": ToSizeInt(mem.cached, "MB"),
    }
    memInfo["memRealUsed"] = (
        memInfo["memTotal"]
        - memInfo["memFree"]
        - memInfo["memBuffers"]
        - memInfo["memCached"]
    )

    memInfo["memUsedPercent"] = memInfo["memRealUsed"] / memInfo["memTotal"] * 100

    return memInfo


def GetMemInfoWindows() -> dict:
    """
    获取内存信息（windows）

    Returns
    -------
    dict
        DESCRIPTION.

    """
    mem = psutil.virtual_memory()
    memInfo: dict = {
        "memTotal": ToSizeInt(mem.total, "MB"),
        "memFree": ToSizeInt(mem.free, "MB"),
        "memRealUsed": ToSizeInt(mem.used, "MB"),
        "menUsedPercent": mem.used / mem.total * 100,
    }

    return memInfo


def ToSizeInt(byte: int, target: str) -> int:
    """
    将字节大小转换为目标单位的大小

    Parameters
    ----------
    byte : int
        int格式的字节大小（bytes size）
    target : str
        目标单位，str.

    Returns
    -------
    int
        转换为目标单位后的字节大小.

    """
    return int(byte / 1024 ** (("KB", "MB", "GB", "TB").index(target) + 1))


def ToSizeString(byte: int) -> str:
    """
    获取字节大小字符串

    Parameters
    ----------
    byte : int
        int格式的字节大小（bytes size）.

    Returns
    -------
    str
        自动转换后的大小字符串，如：6.90 GB.

    """
    units: tuple = ("b", "KB", "MB", "GB", "TB")
    re = lambda: "{:.2f} {}".format(byte, u)
    for u in units:
        if byte < 1024:
            return re()
        byte /= 1024
    return re()


def GetDiskInfo() -> list:
    """
    获取磁盘信息（多平台）

    Returns
    -------
    list
        列表.

    """
    try:
        if UNIX:
            return GetDiskInfoUnix()
        return GetDiskInfoWindows()
    except Exception as err:
        print("获取磁盘信息异常（unix: {}）：".format(UNIX), err)
        return []


def GetDiskInfoWindows() -> list:
    """
    获取磁盘信息Windows

    Returns
    -------
    diskInfo : list
        列表.

    """
    diskIo: list = psutil.disk_partitions()
    diskInfo: list = []
    for disk in diskIo:
        tmp: dict = {}
        try:
            tmp["path"] = disk.mountpoint.replace("\\", "/")
            usage = psutil.disk_usage(disk.mountpoint)
            tmp["size"] = {
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": usage.percent,
            }
            tmp["fstype"] = disk.fstype
            tmp["inodes"] = False
            diskInfo.append(tmp)
        except:
            pass
    return diskInfo


def GetDiskInfoUnix() -> list:
    """
    获取硬盘分区信息（unix）

    Returns
    -------
    list
        DESCRIPTION.

    """
    temp: list = (ExecShellUnix("df -h -P|grep '/'|grep -v tmpfs")[0]).split("\n")
    tempInodes: list = (ExecShellUnix("df -i -P|grep '/'|grep -v tmpfs")[0]).split("\n")
    diskInfo: list = []
    n: int = 0
    cuts: list = [
        "/mnt/cdrom",
        "/boot",
        "/boot/efi",
        "/dev",
        "/dev/shm",
        "/run/lock",
        "/run",
        "/run/shm",
        "/run/user",
    ]
    for tmp in temp:
        n += 1
        try:
            inodes: list = tempInodes[n - 1].split()
            disk: list = tmp.split()
            if len(disk) < 5:
                continue
            if disk[1].find("M") != -1:
                continue
            if disk[1].find("K") != -1:
                continue
            if len(disk[5].split("/")) > 10:
                continue
            if disk[5] in cuts:
                continue
            if disk[5].find("docker") != -1:
                continue
            arr = {}
            arr["path"] = disk[5]
            tmp1 = [disk[1], disk[2], disk[3], disk[4]]
            arr["size"] = tmp1
            # arr['inodes'] = [inodes[1],inodes[2],inodes[3],inodes[4]]
            diskInfo.append(arr)
        except Exception as ex:
            print("信息获取错误：", str(ex))
            continue
    return diskInfo


def md5(strings: str) -> str:
    """
    生成md5

    Parameters
    ----------
    strings : TYPE
        要进行hash处理的字符串

    Returns
    -------
    str[32]
        hash后的字符串.

    """

    m = hashlib.md5()
    m.update(strings.encode("utf-8"))
    return m.hexdigest()


def GetErrorInfo() -> str:
    """
    获取traceback中的错误

    Returns
    -------
    str
        DESCRIPTION.

    """
    import traceback

    errorMsg = traceback.format_exc()
    return errorMsg


def ExecShellUnix(cmdstring: str, shell=True):
    """
    执行Shell命令（Unix）

    Parameters
    ----------
    cmdstring : str
        DESCRIPTION.
    shell : TYPE, optional
        DESCRIPTION. The default is True.

    Returns
    -------
    a : TYPE
        DESCRIPTION.
    e : TYPE
        DESCRIPTION.

    """
    a: str = ""
    e: str = ""
    import subprocess, tempfile

    try:
        rx: str = md5(cmdstring)
        succ_f = tempfile.SpooledTemporaryFile(
            max_size=4096,
            mode="wb+",
            suffix="_succ",
            prefix="btex_" + rx,
            dir="/dev/shm",
        )
        err_f = tempfile.SpooledTemporaryFile(
            max_size=4096,
            mode="wb+",
            suffix="_err",
            prefix="btex_" + rx,
            dir="/dev/shm",
        )
        sub = subprocess.Popen(
            cmdstring,
            close_fds=True,
            shell=shell,
            bufsize=128,
            stdout=succ_f,
            stderr=err_f,
        )
        sub.wait()
        err_f.seek(0)
        succ_f.seek(0)
        a = succ_f.read()
        e = err_f.read()
        if not err_f.closed:
            err_f.close()
        if not succ_f.closed:
            succ_f.close()
    except Exception as err:
        print(err)
    try:
        if type(a) == bytes:
            a = a.decode("utf-8")
        if type(e) == bytes:
            e = e.decode("utf-8")
    except Exception as err:
        print(err)

    return a, e


def GetNetWork() -> dict:
    """
    获取系统网络信息

    Returns
    -------
    dict
        DESCRIPTION.

    """
    networkIo: list = [0, 0, 0, 0]
    cache_timeout: int = 86400
    try:
        networkIo = psutil.net_io_counters()[:4]
    except:
        pass

    otime = cache.get("otime")
    if not otime:
        otime = time.time()
        cache.set("up", networkIo[0], cache_timeout)
        cache.set("down", networkIo[1], cache_timeout)
        cache.set("otime", otime, cache_timeout)

    ntime = time.time()
    networkInfo: dict = {"up": 0, "down": 0}
    networkInfo["upTotal"] = networkIo[0]
    networkInfo["downTotal"] = networkIo[1]
    try:
        networkInfo["up"] = round(
            float(networkIo[0] - cache.get("up")) / 1024 / (ntime - otime), 2
        )
        networkInfo["down"] = round(
            float(networkIo[1] - cache.get("down")) / 1024 / (ntime - otime), 2
        )
    except:
        pass

    networkInfo["downPackets"] = networkIo[3]
    networkInfo["upPackets"] = networkIo[2]

    cache.set("up", networkIo[0], cache_timeout)
    cache.set("down", networkIo[1], cache_timeout)
    cache.set("otime", time.time(), cache_timeout)

    return networkInfo


def GetIoReadWrite() -> Dict[str, int]:
    """
    获取系统IO读写

    Returns
    -------
    dict
        DESCRIPTION.

    """
    ioDisk = psutil.disk_io_counters()
    ioTotal: dict = {}
    ioTotal["write"] = GetIoWrite(ioDisk.write_bytes)
    ioTotal["read"] = GetIoRead(ioDisk.read_bytes)
    return ioTotal


def GetIoWrite(ioWrite: int) -> int:
    """
    获取IO写

    Parameters
    ----------
    ioWrite : TYPE
        DESCRIPTION.

    Returns
    -------
    int
        DESCRIPTION.

    """
    diskWrite: int = 0
    oldWrite: int = cache.get("io_write")
    if not oldWrite:
        cache.set("io_write", ioWrite)
        return diskWrite

    oldTime: float = cache.get("io_time")
    newTime: float = time.time()
    if not oldTime:
        oldTime = newTime
    ioEnd: int = ioWrite - oldWrite
    timeEnd: float = time.time() - oldTime
    if ioEnd > 0:
        if timeEnd < 1:
            timeEnd = 1
        diskWrite = ioEnd / timeEnd
    cache.set("io_write", ioWrite)
    cache.set("io_time", newTime)
    if diskWrite > 0:
        return int(diskWrite)
    return 0


def GetIoRead(ioRead):
    """
    读取IO读

    Parameters
    ----------
    ioRead : TYPE
        DESCRIPTION.

    Returns
    -------
    TYPE
        DESCRIPTION.

    """
    diskRead: int = 0
    oldRead: int = cache.get("io_read")
    if not oldRead:
        cache.set("io_read", ioRead)
        return diskRead
    oldTime: float = cache.get("io_time")
    newTime: float = time.time()
    if not oldTime:
        oldTime = newTime
    ioEnd: int = ioRead - oldRead
    timeEnd: float = time.time() - oldTime
    if ioEnd > 0:
        if timeEnd < 1:
            timeEnd = 1
        diskRead = ioEnd / timeEnd
    cache.set("io_read", ioRead)
    if diskRead > 0:
        return int(diskRead)
    return 0


def GetRegValue(key: str, subkey: str, value: str) -> Any:
    """
    获取系统注册表信息

    Parameters
    ----------
    key : str
        类型.
    subkey : str
        路径.
    value : str
        key.

    Returns
    -------
    value : Any
        DESCRIPTION.

    """
    import winreg

    key = getattr(winreg, key)
    handle = winreg.OpenKey(key, subkey)
    (value, type) = winreg.QueryValueEx(handle, value)
    return value


def GetSystemVersion() -> str:
    """
    获取操作系统版本（多平台）

    Returns
    -------
    str
        DESCRIPTION.

    """
    if UNIX:
        return GetSystemVersionUnix()
    return GetSystemVersionWindows()


def GetSystemVersionWindows() -> str:
    """
    获取操作系统版本（windows）

    Returns
    -------
    str
        DESCRIPTION.

    """
    try:
        import platform

        bit: str = "x86"
        if "PROGRAMFILES(X86)" in os.environ:
            bit = "x64"

        def get(key: str):
            return GetRegValue(
                "HKEY_LOCAL_MACHINE",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                key,
            )

        osName = get("ProductName")
        build = get("CurrentBuildNumber")

        version: str = "{} (build {}) {} (Py{})".format(
            osName, build, bit, platform.python_version()
        )
        return version
    except Exception as ex:
        print("获取系统版本失败，错误：" + str(ex))
        return "未知系统版本."


def GetSystemVersionUnix() -> str:
    """
    获取系统版本（unix）

    Returns
    -------
    str
        系统版本.

    """
    try:
        version: str = readFile("/etc/redhat-release")
        if not version:
            version = (
                readFile("/etc/issue")
                .strip()
                .split("\n")[0]
                .replace("\\n", "")
                .replace("\l", "")
                .strip()
            )
        else:
            version = (
                version.replace("release ", "")
                .replace("Linux", "")
                .replace("(Core)", "")
                .strip()
            )
        v = sys.version_info
        return version + "(Py {}.{}.{})".format(v.major, v.minor, v.micro)
    except Exception as err:
        print("获取系统版本失败，错误：", err)
        return "未知系统版本."


def GetBootTime() -> dict:
    """
    获取当前系统启动时间

    Returns
    -------
    dict
        DESCRIPTION.

    """
    bootTime: float = psutil.boot_time()
    return {
        "timestamp": bootTime,
        "runtime": time.time() - bootTime,
        "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
    }


def ShellCommand(command: str) -> str:
    return os.popen(command).read().strip()


def GetProductInfo() -> dict:
    querySql = "mysql -usmc -p{} -e \"select * from t_sys_param_init where paramName = '{}';\" SMC | tail -1 | cut -d'\t' -f5"
    product: dict = {
        # SMCVersion / deviceModel / proVersion / hardwareVersion / evtVersion
        "software_version": ShellCommand(querySql.format(dbpasswd, "SMCVersion")),
        "device_mode": ShellCommand(querySql.format(dbpasswd, "deviceModel")),
        "product_version": ShellCommand(querySql.format(dbpasswd, "proVersion")),
        "evt_version": ShellCommand(querySql.format(dbpasswd, "evtVersion")),
        "hardware_version": ShellCommand(querySql.format(dbpasswd, "hardwareVersion")),
    }

    return product


def GetSystemInfo() -> dict:
    global clearLimit, storeDaysDisk, elasticsearchHost

    fp = readFile("/proc/cpuinfo")
    cpuInfo = re.findall("model.*?name.*?:\s+(.*)", fp)
    mp = readFile("/proc/meminfo")
    memInfo = sum([int(i) for i in re.findall("MemTotal:\s*(\d+)", mp)])
    diskTotal = GetDiskInfoUnix()
    """
       1. Calculate the average EPS in 1 minute
       2. Calculate the elasticsearch storage rate in 1 minute
           elasticsearchHost: host ip
           elasticsearchDatestatus: curl query statement
           elasticsearchJsonkeys: event-xxx array
           elasticsearchLibrary: library being written
           xx_store_eps: eps
           xx_store_eps: store
    """
    elasticsearchHost = re.search(
        "host:\s* (\d+.\d+.\d+.\d+)", readFile("/etc/elasticsearch/elasticsearch.yml")
    ).group(1)
    elasticsearchDatestatus = (
        "curl http://{}:9200/event_{}*/_stats?pretty 2>/dev/null".format(
            elasticsearchHost, time.strftime("%Y%m%d", time.localtime())
        )
    )
    elasticsearchJson = json.loads(ShellCommand(elasticsearchDatestatus))
    elasticsearchJsonkeys: list = elasticsearchJson["indices"].keys()
    elasticsearchJsonkeys = list(
        filter(lambda x: x.find("event") >= 0, elasticsearchJsonkeys)
    )
    elasticsearchLibrary = max(elasticsearchJsonkeys)

    oldStoreEps = json.loads(ShellCommand(elasticsearchDatestatus))["indices"][
        elasticsearchLibrary
    ]["primaries"]["store"]["size_in_bytes"]
    oldReciveEps = re.search(
        "(\d+)", ShellCommand('netstat -uds | grep "packets received"')
    ).group()
    time.sleep(60)
    newStoreEps = json.loads(ShellCommand(elasticsearchDatestatus))["indices"][
        elasticsearchLibrary
    ]["primaries"]["store"]["size_in_bytes"]
    newReciveEps = re.search(
        "(\d+)", ShellCommand('netstat -uds | grep "packets received"')
    ).group()

    """
       Can 180 logs be stored ?
       totalStores: total storage size (bytes)
       storeDays: store days (d)
    """
    elasticsearchAllstatus = "curl http://{}:9200/_stats?pretty 2>/dev/null".format(
        elasticsearchHost
    )
    storeDays = "curl http://{}:9200/_cat/indices?format=json 2>/dev/null".format(
        elasticsearchHost
    )
    clearLimit = "mysql -uroot -p{} -e \"select paramValue from t_sys_param_init where paramName = 'DiskClearByLimit';\" SMC | tail -1".format(
        dbpasswd
    )

    elasticsearchJson = json.loads(ShellCommand(elasticsearchAllstatus))
    totalStores = elasticsearchJson["_all"]["primaries"]["store"]["size_in_bytes"]
    storeDaysDisk = list(set(re.findall("(event_\d{8})", ShellCommand(storeDays))))
    storeDays = len(list(set(re.findall("(event_\d{8})", ShellCommand(storeDays)))))
    clearLimit = ShellCommand(clearLimit)
    storeEveryDay = "%.f" % (totalStores / storeDays)

    storePath = ["/data" if os.path.exists("/data") else "/opt"][0]
    storePathbytes = ShellCommand("du -sb {} | cut -f1".format(storePath))
    availStore = "%.f" % (int(storePathbytes) * (int(clearLimit) / 100))
    availStoreDays = "%.f" % (int(availStore) / int(storeEveryDay))
    # clean days
    delLimit = "mysql -uroot -p{} -e \"select paramValue from t_sys_param_init where paramName = 'DiskClearByTime';\" SMC | tail -1".format(
        dbpasswd
    )
    delDays = ShellCommand(delLimit)

    systemInfo: dict = {
        "CpuModuleCore": "{}".format(cpuInfo[0]),
        "CpuCore": "{}".format(len(cpuInfo)),
        "MEM": "%.1f" % (memInfo / 1024 / 1024) + "G",
        "DISK": diskTotal,
        "AverageOneMinuteEPS": str(
            "%.1f" % ((int(newReciveEps) - int(oldReciveEps)) / 60)
        )
        + " Eps/s",
        "AverageOneMinuteStore": str(
            "%.1f" % (((int(newStoreEps) - int(oldStoreEps)) / 1024 / 1024 / 60))
        )
        + " M/s",
        "DiskCleanLimit": str(int(clearLimit)) + "%",
        "DiskCleanDays": str(delDays) + "d",
        "LogStorageDays": str(availStoreDays) + "d",
    }

    return systemInfo


def ProductStatus() -> dict:
    status_map = {
        "1": "正常",
        "2": "异常",
    }
    querySql = 'mysql -uroot -p{} -e "select compName,compStatus from t_cmp_status where compStatus = 1 group by compName;" SMC | xargs'
    throwLog = "mysql -uroot -p{} -e \"select * from t_sys_log where componentName='采集控制器' and logContent like '%丢弃事件%' order by  createTime desc limit 10;\" SMC".format(
        dbpasswd
    )

    moduleStatus = ShellCommand(querySql.format(dbpasswd)).split()[2:]

    pro_status: dict = {}
    for comp in moduleStatus[::2]:
        pro_status[comp] = moduleStatus[moduleStatus.index(comp) + 1]

    pro_status = {
        key: "异常" if value == "2" else "正常" for (key, value) in pro_status.items()
    }

    pro_status["ThrowLog"] = os.popen(throwLog).read() if os.popen(throwLog).read() else "无"
    return pro_status


def GetDiskSpeed() -> dict:
    disk_speed: dict = {
        "disk_write": ShellCommand(
            "dd if=/dev/zero of=/opt/smc/elasticsearch/data/test.dbf bs=1M count=1000 oflag=direct 2> /tmp/wirtebytes; cat /tmp/wirtebytes | tail -1 | cut -d',' -f3"
        ),
        "disk_read": ShellCommand(
            "dd if=/opt/smc/elasticsearch/data/test.dbf of=/dev/null bs=1M count=1000 iflag=direct 2>/tmp/readbytes; cat /tmp/readbytes | tail -1 | cut -d',' -f3"
        ),
    }

    return disk_speed


def DiskClear() -> str:
    """
    DISK CLEAR CHECK
    """

    delLimit = "mysql -uroot -p{} -e \"select paramValue from t_sys_param_init where paramName = 'DiskClearByTime';\" SMC | tail -1".format(
        dbpasswd
    )

    delDays = ShellCommand(delLimit)
    delDaysDate = "event_" + ShellCommand(
        'currentDate=`date +%F`;date -d "$currentDate - {} day" +%Y%m%d'.format(delDays)
    )
    diskAllInfo = GetDiskInfoUnix()

    disk_map: dict = {}
    defaltPath = "/opt"
    for disk in diskAllInfo:
        if disk.get("path") == "/data":
            defaltPath = "/data"
            disk_map = disk
            break
        elif disk.get("path") == "/opt":
            disk_map = disk

    if (int(disk_map.get("size")[-1].replace("%", "")) - int(clearLimit) >= 3) or (
        delDaysDate > min(storeDaysDisk)
    ):
        return "清理机制异常"
    else:
        return "清理机制正常"


def ElasticsearchStatus() -> str:
    querySql = "curl http://{}:9200/_cat/health?v 2>/dev/null | grep red".format(
        elasticsearchHost
    )
    if ShellCommand(querySql):
        return "索引库状态异常"
    else:
        return "索引库状态正常"


def WriteFile(key, value) -> None:
    with open("systemLogs", "a+", encoding="utf-8") as wp:
        # wp.write("*****" + key + "*****" + "\n\n" + value)
        pp = PrettyTable(["组件名称","错误日志"])
        if value:
            pp.add_row([key,"有"])
        else:
            pp.add_row([key,"无"])
        ###  FORMAT TABLE
        pp.junction_char = '$'
        pp.horizontal_char = '+'
        pp.vertical_char = '%'
        wp.write(str(pp)+ "\n\n")


def GetModulesLogs() -> dict:
    clusterName = re.search(
        "cluster.name:\s*(.*)", readFile("/etc/elasticsearch/elasticsearch.yml")
    ).group(1)

    modules_map: dict = {
        "elasticsearch": "/opt/data/logs/elasticsearch/{}.log".format(clusterName),
        "eventmonitor": "/opt/data/logs/eventmonitor/eventMonitor.log",
        "file_store": "/opt/smc/storage/log/file_store.log",
        "web": "/opt/data/logs/tomcat/smc_error.log",
        "data_analyser": "/opt/smc/kernel/log/data_analyser.log",
        "resp_center": "/opt/smc/kernel/log/resp_center.log",
        "business_manager": "/opt/smc/kernel/log/business_manager.log",
        "collect_controller": "/opt/smc/sensor/log/collect_controller.log",
    }

    queryShell = "cat {} | egrep 'error|Error|ERROR'"
    errorBeforeLogs = "egrep -n -A 20 'error|Error|ERROR' {}"
    errorAfterLogs = "egrep -n -B 10 'error|Error|ERROR' {}"

    module_logs: dict = {}
    for module, path in modules_map.items():
        queryResult = ShellCommand(queryShell.format(path))
        if queryResult:
            try:
                Result = (
                    os.popen(errorBeforeLogs.format(path)).read()
                    + "\n"
                    + os.popen(errorAfterLogs.format(path)).read()
                )
            except UnicodeDecodeError:
                Result = (
                    os.popen(errorBeforeLogs.format(path))
                    ._stream.buffer.read()
                    .decode("latin1")
                    + "\n"
                    + os.popen(errorAfterLogs.format(path))
                    ._stream.buffer.read()
                    .decode("latin1")
                )

            module_logs[module] = Result
        else:
            Result = ""
            module_logs[module] = Result
        WriteFile(module, Result)

    with open("systemLogs", "a+", encoding="utf-8") as wp:
        for key,value in module_logs.items():
            if value:
                wp.write("**************************************{}**************************************".format(key) + "\n\n")
                wp.write(value)


def LogAccessStatus() -> dict:
    """
    Check device access status
    --------------------------
    example:
      accessInfo:
        {
          'key': '192.168.100.123',
          'doc_count': 36823949,
          'eventNameCount': {
             'doc_count_error_upper_bound': 0,
             'sum_other_doc_count': 0,
             'buckets': [{'key': '通用日志', 'doc_count': 6498423}]},
          'maxReviceTime': {
             'value': 1661351878.0,
             'value_as_string': ' 1661351878'
          }
        }
    """

    querySql = 'mysql -uroot -p{} -e "select logSourceIP from t_sys_logSource where status = 1;" SMC '.format(
        dbpasswd
    )
    accessIp = ShellCommand(querySql)
    accessIp = re.findall("(\d+.\d+.\d+.\d+)", accessIp)

    deviceIp = ""
    for i, ip in enumerate(accessIp):
        if i == len(accessIp) - 1:
            deviceIp += ip
        else:
            deviceIp += ip + " OR "

    queryCurl = """ curl -XGET -H "Content-Type: application/json" 'http://%s:9200/event_%s/_search?pretty' -d '
    {
      "size":0,
      "query":{
         "query_string":{
             "query":"deviceaddress: (%s)"
         }
      },
      "aggs":{
         "group_by_ip": {
             "terms":{"field": "deviceaddress"},
             "aggs":{
               "eventNameCount":{
                 "terms":{
                    "field": "eventname.raw",
                    "include": "通用日志"
                 }
               },
               "maxReviceTime":{
                 "max":{
                   "field": "receivetime",
                   "format": " "
                 }
               }
             }
         }
      }
    } 
    ' 2>/dev/null""" % (
        elasticsearchHost,
        time.strftime("%Y%m%d", time.localtime()),
        deviceIp,
    )
    accessInfo = json.loads(os.popen(queryCurl).read())
    accessInfo = accessInfo["aggregations"]["group_by_ip"]["buckets"]

    print (accessInfo)

    log_access: dict = {}
    for ip_map in accessInfo:
        ip = ip_map["key"]
        buckets = ip_map["eventNameCount"]["buckets"]
        docCount = ip_map["doc_count"]
        if len(buckets) == 0 and int(docCount) >= 1:
            log_access[ip] = "接入正常"
        elif len(buckets) > 0:
            log_access[ip] = "存在通用日志"
        else:
            log_access[ip] = "无日志接入"

    return log_access


def GetCpuConstants() -> dict:
    """
    获取CPU常量信息

    Parameters
    ----------
    cpuConstants : CpuConstants
        DESCRIPTION.

    Returns
    -------
    dict
        DESCRIPTION.

    """
    return cpuConstants.getDict


def GetFullSystemData() -> dict:
    """
    获取完全的系统信息

    Returns
    -------
    dict
        DESCRIPTION.

    """
    systemData: dict = {
        **GetSystemInfo(),
        "boot": {**GetBootTime()},
        "product": GetProductInfo(),
        "systemStatus": ProductStatus(),
        "diskClear": DiskClear(),
        "elasticsearchStatus": ElasticsearchStatus(),
        "logAccess": LogAccessStatus(),
        "diskSpeed": GetDiskSpeed(),
    }
    return systemData


def HandlerFunc(allCollectInfo: dict) -> None:
    """
    deal with all collect info
      1. print
      2. write systemLogs
    """
    diskTotal = re.search(
        'diskTotal\s*:"(.*?)"',
        ShellCommand("perl /opt/smc/hardware/sbin/hw_info.pl query hardwareinfo"),
    ).group(1)
    ### cpuinfo PrettyTable
    cpuInfo = PrettyTable(
        ["CPU型号", "CPU核数", "内存容量", "硬盘总量", "硬盘路径", "容量", "已使用", "可用", "使用占比"]
    )
    cpuInfo.add_row(
        [
            allCollectInfo["CpuModuleCore"],
            allCollectInfo["CpuCore"],
            allCollectInfo["MEM"],
            diskTotal,
            allCollectInfo["DISK"][0]["path"],
            allCollectInfo["DISK"][0]["size"][0],
            allCollectInfo["DISK"][0]["size"][1],
            allCollectInfo["DISK"][0]["size"][2],
            allCollectInfo["DISK"][0]["size"][3],
        ]
    )

    del allCollectInfo["DISK"][0]
    for info in allCollectInfo["DISK"]:
        cpuInfo.add_row(
            [
                "",
                "",
                "",
                "",
                "\n" + info["path"],
                "\n" + info["size"][0],
                "\n" + info["size"][1],
                "\n" + info["size"][2],
                "\n" + info["size"][3],
            ]
        )

    ### storeInfo
    storeInfo = PrettyTable(["分钟平均EPS", "分钟存储速率", "磁盘清理阈值", "磁盘清理天数", "预计日志存储天数"])
    storeInfo.add_row(
        [
            allCollectInfo["AverageOneMinuteEPS"],
            allCollectInfo["AverageOneMinuteStore"],
            allCollectInfo["DiskCleanLimit"],
            allCollectInfo["DiskCleanDays"],
            allCollectInfo["LogStorageDays"],
        ]
    )

    ### timeInfo
    timeInfo = PrettyTable(["时间戳", "运行时间(h)", "时间"])
    timeInfo.add_row(
        [
            allCollectInfo["boot"]["timestamp"],
            int(int(allCollectInfo["boot"]["runtime"]) / 60 / 60),
            allCollectInfo["boot"]["datetime"],
        ]
    )

    ### productInfo
    productInfo = PrettyTable(["软件版本号", "硬件版本号", "基础库版本", "标准化版本", "产品型号"])
    productInfo.add_row(
        [
            allCollectInfo["product"]["software_version"],
            allCollectInfo["product"]["hardware_version"],
            allCollectInfo["product"]["device_mode"],
            allCollectInfo["product"]["product_version"],
            allCollectInfo["product"]["evt_version"],
        ]
    )

    ### moduleInfo
    moduleInfo = PrettyTable(["业务管理器", "响应中心", "数据分析器", "采集器", "采集控制器"])
    moduleInfo.add_row(
        [
            allCollectInfo["systemStatus"]["业务管理器"],
            allCollectInfo["systemStatus"]["响应中心"],
            allCollectInfo["systemStatus"]["数据分析器"],
            allCollectInfo["systemStatus"]["采集器"],
            allCollectInfo["systemStatus"]["采集控制器"],
        ]
    )

    ### clearInfo
    clearInfo = PrettyTable(["磁盘清理机制", "索引库状态", "磁盘写速率", "磁盘读速率", "丢弃的日志"])
    clearInfo.add_row(
        [
            allCollectInfo["diskClear"],
            allCollectInfo["elasticsearchStatus"],
            allCollectInfo["diskSpeed"]["disk_write"],
            allCollectInfo["diskSpeed"]["disk_read"],
            allCollectInfo["systemStatus"]["ThrowLog"],
        ]
    )

    ### logAccessInfo
    logAccessInfo = PrettyTable(["设备地址", "接入状态"])
    for ip,status in allCollectInfo["logAccess"].items():
        logAccessInfo.add_row([ip, status])

    ### moduleInfo
    #moduleInfo = PrettyTable(["产品组件", "错误日志"])
    #for md, log in allCollectInfo["modulesLog"].items():
    #    moduleInfo.add_row([md,log])

    with open("systemLogs","w+", encoding="utf-8") as sl:
        for table in [ cpuInfo , storeInfo, timeInfo, productInfo, moduleInfo, clearInfo, logAccessInfo]:
            sl.write(str(table) + "\n\n")
    GetModulesLogs()


if __name__ == "__main__":
    # {'CPU型号和核数': 'Intel(R) Xeon(R) CPU E3-1231 v3 @ 3.40GHz 8核', '内存容量': '31.4G', '硬盘信息': [{'path': '/', 'size': ['16G', '4.5G', '11G', '31%']}, {'path': '/data', 'size': ['1.8T', '1.5T', '360G', '81%']}, {'path': '/opt', 'size': ['16G', '5.1G', '11G', '32%']}], '一分钟平均eps': '134.8 Eps/s', '一分钟存储速率': '0.1 M/s', '磁盘清理阈值': '85%', '磁盘清理天数': '190d', '预计日志存储天数': '26d', 'boot': {'timestamp': 1660220124.0, 'runtime': 1104984.941680193, 'datetime': '2022-08-24 15:11:48'}, 'product': {'software_version': 'V5.0.8', 'device_mode': 'JUMING-SAS-100AH', 'product_version': 'Pro.2022.06.29.008001', 'evt_version': 'Evt.2022.04.02.004170', 'hardware_version': 'V1.0'}, 'systemStatus': {'业务管理器': '正常', '响应中心': '正常', '数据分析器': '正常', '采集器': '正常', '采集控制器': '正常'}, 'diskClear': '清理机制正常', 'elasticsearchStatus': '索引库状态正常', 'logAccess': {'192.168.100.123': '存在通用日志', '192.168.100.124': '接入正常', '192.168.11.10': '接入正常', '192.168.11.11': '接入正常'}}

    # {'CpuModuleCore': 'Intel(R) Xeon(R) CPU E3-1231 v3 @ 3.40GHz', 'CpuCore': '8', 'MEM': '31.4G', 'DISK': [{'path': '/', 'size': ['16G', '4.6G', '11G', '31%']}, {'path': '/data', 'size': ['1.8T', '1.5T', '349G', '81%']}, {'path': '/opt', 'size': ['16G', '5.1G', '11G', '32%']}], 'AverageOneMinuteEPS': '133.0 Eps/s', 'AverageOneMinuteStore': '0.0 M/s', 'DiskCleanLimit': '85%', 'DiskCleanDays': '190d', 'LogStorageDays': '26d', 'boot': {'timestamp': 1660220122.0, 'runtime': 1114273.97271204, 'datetime': '2022-08-24 17:46:35'}, 'product': {'software_version': 'V5.0.8', 'device_mode': 'JUMING-SAS-100AH', 'product_version': 'Pro.2022.06.29.008001', 'evt_version': 'Evt.2022.04.02.004170', 'hardware_version': 'V1.0'}, 'systemStatus': {'业务管理器': '正常', '响应中心': '正常', '数据分析器': '正常', '采集器': '正常', '采集控制器': '正常'}, 'diskClear': '清理机制正常', 'elasticsearchStatus': '索引库状态正常', 'logAccess': {'192.168.100.123': '存在通用日志', '192.168.100.124': '接入正常', '192.168.11.10': '接入正常', '192.168.11.11': '接入正常'}, 'diskSpeed': {'disk_write': '86.4 MB/s', 'disk_read': '127 MB/s'}}

    allCollectInfo = GetFullSystemData()
    HandlerFunc(allCollectInfo)

    # with open("systemLogs","a+", encoding="utf-8") as sl:
    #    sl.write(str(cpuInfo) + "\n\n")
