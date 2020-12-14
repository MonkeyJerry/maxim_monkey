import logging
import re
import os
import sys
import time
import subprocess
from itertools import groupby

from appetizer import insights
from utils.path_process import PathProcess
from utils.report_json_process import ReportJsonProcess


class LogErrorProcess:
    def __init__(self):
        self.extracted_crash_log_list = []
        self.extracted_crash_log_str_list = []
        self.ext_path = PathProcess.THIS_FILE_PATH_EXT
        self.path = PathProcess()
        self.report_json = ReportJsonProcess()
        self.test_apk = "{}/{}".format(self.report_json.apk_path, self.report_json.get_apk())
        self.pkg = insights.get_apk_package(self.test_apk)

    def upload_log_error_file(self):
        print("upload log_error_dzh.....")
        if insights.installed_check(self.test_apk):
            self.test_apk_version = float(list(
                insights.adb_android('shell pm dump {} | grep "versionName"'.format(self.pkg), showCmd=True,
                                     stdout=subprocess.PIPE, universal_newlines=True).stdout)[0].split('=')[-1].strip())
        else:
            logging.error("please install your test apk in your device first")
            sys.exit(1)
        if self.test_apk_version >= 9.23:
            insights.adb_android(
                'pull /sdcard/Android/data/com.android.dazhihui/cache/log/log_error_dzh.txt "{}/data"'.format(
                    self.ext_path), showCmd=True)
        else:
            insights.adb_android('pull /sdcard/log_error_dzh.txt "{}/data"'.format(self.ext_path), showCmd=True)
        time.sleep(5)

    # def extract_crash_log(self):
    #     index = 0
    #     log_error_file = "{}/data/log_error_dzh.txt".format(self.ext_path)
    #     if os.path.exists(log_error_file):
    #     with open(log_error_file, "r", encoding='utf-8') as f:
    #         for (line, stacktrace) in enumerate(f):
    #             if not re.findall("---->", stacktrace) and re.findall('java', stacktrace):
    #                 index += 1
    #                 self.extracted_crash_log_list.append((index, line, stacktrace))
    # return self.extracted_crash_log_list
    def extract_crash_log(self):
        index = 0
        log_error_file = "{}/data/log_error_dzh.txt".format(self.ext_path)
        if os.path.exists(log_error_file):
            import codecs
            with codecs.open(log_error_file, "r", encoding='utf-8', errors='ignore') as f:
                for (line, stacktrace) in enumerate(f):
                    # print(line, stacktrace)
                    if not re.findall("---->", stacktrace) and (
                            re.findall('java', stacktrace) or re.findall('Unknown Source',
                                                                         stacktrace) or re.findall('Native Method',
                                                                                                   stacktrace)):
                        line += 1
                        index += 1
                        # stacktrace = stacktrace.strip('\n')
                        # print(index, line, stacktrace)
                        self.extracted_crash_log_list.append((index, line, stacktrace))
            return self.extracted_crash_log_list

    # def get_crash_log_dict(self):
    #     if self.extracted_crash_log_list:
    #         group_lst = []
    #         for key, group in groupby(self.extracted_crash_log_list, lambda x: x[1] - x[0]):
    #             group_lst.append(list(group))
    #
    #         crash_log_str = ''
    #         for i in range(len(group_lst)):
    #             for j in group_lst[i]:
    #                 crash_log_str += j[2]
    #             if crash_log_str.find("cairh") == -1:
    #                 self.extracted_crash_log_str_list.append(crash_log_str)
    #     return {"log_error": self.extracted_crash_log_str_list}
    def get_crash_log_dict(self):
        if self.extracted_crash_log_list:
            # print(self.extracted_crash_log_str_list)
            # group_lst = []
            for key, group in groupby(self.extracted_crash_log_list, lambda x: x[1] - x[0]):
                grouped_stacktrace_str = "".join(item[2] for item in list(group))
                if grouped_stacktrace_str.find("cairh") == -1:
                    self.extracted_crash_log_str_list.append(grouped_stacktrace_str)
        return {"log_error": self.extracted_crash_log_str_list}


if __name__ == '__main__':
    log_error = LogErrorProcess()
    log_error.upload_log_error_file()
    log_error.extract_crash_log()
    crash_log_dict = log_error.get_crash_log_dict()
    # log_error.update_data_json_file(crash_log_dict)
