import atexit
import logging
import os
import shutil
import subprocess
import sys
import time

from utils.log_error_process import LogErrorProcess
from utils.data_json_update import DataJsonUpdate
from utils.path_process import PathProcess
from appetizer import insights
from utils.report_json_process import ReportJsonProcess


class Maxim:
    def __init__(self, is_clear_apk_cache=False):
        self.log_error = LogErrorProcess()
        self.data_json = DataJsonUpdate()
        self.path = PathProcess()
        self.report_json = ReportJsonProcess()
        self.test_apk = "{}/{}".format(self.report_json.apk_path, self.report_json.get_apk())
        self.pkg = insights.get_apk_package(self.test_apk)
        self.is_clear_apk_cache = is_clear_apk_cache

    def setup(self):
        try:
            insights.adb_android("version", showCmd=True)
        except:
            logging.error("adb not available")
            sys.exit(1)
        # 上传maxim需要的jar包
        try:
            r = insights.adb_android("push max_package/framework.jar /sdcard", showCmd=True, stdout=subprocess.PIPE,
                                     universal_newlines=True)
            for i in r.stdout:
                if "no devices" in i or "more than one device" in i:
                    raise
        except:
            logging.error("no devices/emulators or more than one device/emulator found")
            sys.exit(1)
        insights.adb_android("push max_package/monkey.jar /sdcard", showCmd=True)

        # 若要执行输入需安装ADBKeyBoard
        insights.adb_android("install max_package/ADBKeyBoard.apk", showCmd=True)
        time.sleep(5)
        # 设置ADBKeyBoard为默认输入法
        insights.adb_android("shell ime enable com.android.adbkeyboard/.AdbIME", showCmd=True)
        insights.adb_android("shell ime set com.android.adbkeyboard/.AdbIME", showCmd=True)

        # 上传测试包并下载插桩包到指定目录（不建议，appetizer提供的api上传并插桩时间较长3-5mins且回由于网络原因导致失败）
        # 下载插桩app到指定目录，且删除未插桩app
        # 请在test_apk_appetizer文件夹提前放入待测的未插桩包或者已插桩包
        # self.test_apk = self.report_json.download_appetize_processed_apk()
        # 卸载手机上的相同的被测app并安装插桩app
        # insights.uninstall_android(self.test_apk, showCmd=True)
        # insights.install_android(self.test_apk, showCmd=True)

        # 删除大智慧日志
        insights.adb_android("shell rm -rf /sdcard/log_error_dzh.txt", showCmd=True)

        # 默认不清除apk缓存，即如果账号是登录状态的话则保持登录
        if self.is_clear_apk_cache:
            insights.adb_android("shell rm -rf /sdcard/Android/data/.dzh", showCmd=True)
            insights.adb_android("shell pm clear {} ".format(self.pkg), showCmd=True)
        time.sleep(10)
        # 删除手机上appetizer日志缓存,可不执行，已修改源代码默认删除
        insights.adb_android("shell rm -rf /sdcard/Android/data/{}/files".format(self.pkg), showCmd=True)

        # 执行前再次确认删除手机上的sdcard/maximlog，避免maxim自动创建maximlog.1文件夹，造成数据分析错误
        insights.adb_android("shell rm -rf /sdcard/maximlog", showCmd=True)
        # 再次执行时删除data下所有数据
        for data_item in os.listdir("data"):
            file = "data/{}".format(data_item)
            print(file)
            if os.path.isfile(file):
                os.remove(file)
                print("file removed")
            else:
                shutil.rmtree(file)
                print("dir removed")
        # 转存历史数据
        self.report_json.move_log_data()
        # 给大智慧app授权相关权限
        insights.adb_android("shell pm grant {} android.permission.READ_EXTERNAL_STORAGE".format(self.pkg),
                             showCmd=True)
        # insights.adb_android("shell pm grant com.android.dazhihui android.permission.INTERNET", showCmd=True)
        insights.adb_android("shell pm grant {} android.permission.READ_PHONE_STATE".format(self.pkg), showCmd=True)
        insights.adb_android("shell pm grant {} android.permission.WRITE_EXTERNAL_STORAGE".format(self.pkg),
                             showCmd=True)
        insights.adb_android("shell pm grant {} android.permission.ACCESS_FINE_LOCATION".format(self.pkg), showCmd=True)
        insights.adb_android("shell pm grant {} android.permission.RECORD_AUDIO".format(self.pkg), showCmd=True)
        insights.adb_android("shell pm grant {} android.permission.CAMERA".format(self.pkg), showCmd=True)

        # 上传maxim相关配置
        insights.adb_android("push max_config/max.xpath.actions /sdcard", showCmd=True)
        insights.adb_android("push max_config/max.widget.black /sdcard", showCmd=True)
        insights.adb_android("push max_config/max.config /sdcard", showCmd=True)
        insights.adb_android("push max_config/max.strings /sdcard", showCmd=True)

    def maxim_monkey(self, run_time=60, mode='mix'):
        adb_maxim = ""
        if mode in ["mix", "dfs"]:
            adb_maxim = "shell CLASSPATH=/sdcard/monkey.jar:/sdcard/framework.jar exec app_process /system/bin " \
                        "tv.panda.test.monkey.Monkey -p {0} --throttle 200 --imagepolling --pct-touch 40 --pct-motion " \
                        "20 --pct-pinchzoom 5 --pct-nav 5 --pct-majornav 5 --pct-rotation 1 --uiautomator{1} " \
                        "--running-minutes {2} -v -v -v -v --output-directory /sdcard/maximlog".format(self.pkg, mode,
                                                                                                       run_time)
        else:
            logging.error("wrong maxim monkey mode, only support mix or dfs")
            sys.exit(1)
        if adb_maxim:
            with open("data/maxim.log", "w+") as f:
                r = insights.adb_android(adb_maxim, showCmd=True, stdout=f)
                r.wait()

    def appetize_analyze_and_extract_report(self):
        # 获取appetize分析日志
        try:
            self.report_json.download_report_gz()
            # 解压json.gz
            gz_file = self.report_json.unzip_report_gz()
            print(gz_file)
            return 1
        except:
            logging.error("download or unzip report failed")
            return 0
        # if os.path.exists("data/data.json.gz"):
        #     print("data.json.gz removed")
        #     os.remove("data/data.json.gz")

    def data_process_to_test_report(self):
        insights.adb_android('pull /sdcard/maximlog "{}/data"'.format(self.path.THIS_FILE_PATH_EXT), showCmd=True)
        time.sleep(5)
        # 更新data.json
        self.log_error.upload_log_error_file()
        self.log_error.extract_crash_log()
        crash_log_dict = self.log_error.get_crash_log_dict()
        self.data_json.update_data_json_file(crash_log_dict)


    def teardown(self):
        # 数据清洗，删除手机上的相关数据
        # insights.adb_android("shell rm -rf /sdcard/Android/data/.dzh", showCmd=True)
        insights.adb_android("shell rm -rf /sdcard/log_error_dzh.txt", showCmd=True)
        # insights.adb_android("shell pm clear {}".format(self.pkg), showCmd=True)
        # 删除appetizer日志缓存，可不执行，已修改源代码默认删除
        insights.adb_android("shell rm -rf /sdcard/Android/data/{}/files".format(self.pkg), showCmd=True)
        # 删除手机上maxim相关日志
        insights.adb_android("shell rm -rf /sdcard/maximlog", showCmd=True)
        # 打包数据留存并用于jenkins附件
        self.report_json.zip_log_data()


if __name__ == '__main__':
    maxim = Maxim()
    maxim.setup()
    maxim.maxim_monkey(5)
    maxim.appetize_analyze_and_extract_report()
    maxim.data_process_to_test_report()
    maxim.teardown()
    # maxim.log_error.extract_crash_log()
    # print(maxim.log_error.get_crash_log_dict())

