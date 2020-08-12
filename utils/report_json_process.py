import datetime
import logging
import os
import shutil
import subprocess
import time

import requests
from appetizer import insights
from utils.path_process import PathProcess
import gzip


class ReportJsonProcess:
    def __init__(self):
        self.path = PathProcess()
        self.ext_path = self.path.THIS_FILE_PATH_EXT
        self.apk_path = "{}/test_apk_appetizer".format(self.ext_path)
        self.gz_path = "{}/data".format(self.ext_path)

    def get_apk(self):
        apk = self.path.get_path_file(self.apk_path)
        if len(apk) != 1:
            logging.error("please place your test apk in test_apk_appetizer dir and the num of apk should be one")
        else:
            return apk[0]

    def download_appetize_processed_apk(self):
        is_processed = False
        if self.get_apk():
            test_apk = "{0}/test_apk_appetizer/{1}".format(self.ext_path, self.get_apk())
            is_processed = insights.process(test_apk)
            if is_processed:
                os.remove(test_apk)
        # 等待转存插桩包，最多等待1分钟
        wait_time = 0
        while not os.path.exists("test_apk_appetizer/dzh_debug_appetizer.apk") or wait_time == 60:
            time.sleep(2)
            wait_time += 2
        return "test_apk_appetizer/dzh_debug_appetizer.apk"

    def download_report_gz(self):
        test_apk_appetizer = "{0}/test_apk_appetizer/{1}".format(self.ext_path, self.get_apk())
        download_url = insights.analyze(test_apk_appetizer)
        if download_url:
            print('~~~~~~~~~~downloadurl~~~~~~~~~:' + download_url)
            # download_url = "http://cache.appetizer.io/5ea2aaee07025052872e2744_report.json.gz" #测试地址
            r = requests.get(download_url, stream=True)
            with open("{}/data.json.gz".format(self.gz_path), "wb") as f:
                for chunk in r.iter_content(chunk_size=512):
                    if chunk:
                        f.write(chunk)
        else:
            logging.error("download report failed")

    def unzip_report_gz(self):
        files = self.path.get_path_file("{}/data".format(self.ext_path))
        for file in files:
            if file.endswith('gz'):
                gz_file = "{0}/data/{1}".format(self.ext_path, file)
                unzip_file = gzip.GzipFile(gz_file)
                # datetime.date.today().isoformat().replace('-', '')
                with open('{0}/data/data.json'.format(self.ext_path), "wb+") as f:
                    f.write(unzip_file.read())
                return gz_file
        if not any([file.endswith("gz") for file in files]):
            raise FileNotFoundError("No Report .gz File")

    def zip_log_data(self):
        all_data_path = "{}/data".format(self.path.THIS_FILE_PATH_EXT)
        print("attachment_file", all_data_path)
        shutil.make_archive("{}/attachments_log/data_log_{}".format(self.path.THIS_FILE_PATH_EXT,
                                                                    datetime.datetime.now().strftime("%Y%m%d%H%M%S")),
                            "zip", all_data_path)

    def move_log_data(self):
        src_attachments_data_path = "{}/attachments_log".format(self.path.THIS_FILE_PATH_EXT)
        dst_path = "{}/history_log".format(self.path.THIS_FILE_PATH_EXT)
        for item in os.listdir(src_attachments_data_path):
            src_item = os.path.join(src_attachments_data_path, item)
            if not item.startswith('.'):
                shutil.move(src_item, dst_path)
                # os.remove(src_item)


if __name__ == '__main__':
    report_json = ReportJsonProcess()
    # report_json.download_report_gz()
    # report_json.unzip_report_gz()
    report_json.zip_log_data()
    # report_json.move_log_data()
    # print(datetime.datetime.now().strftime("%Y%m%d%H%M%S"))
