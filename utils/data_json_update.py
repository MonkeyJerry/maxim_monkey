import json
import os

from utils.path_process import PathProcess


class DataJsonUpdate:
    def __init__(self):
        self.ext_path = PathProcess.THIS_FILE_PATH_EXT

    def update_data_json_file(self, crash_log_dict):
        data_json_file = "{}/data/data.json".format(self.ext_path)

        if os.path.exists(data_json_file):
            with open(data_json_file) as f:
                data = f.read()
                data_dict = json.loads(data)
                data_dict.update(crash_log_dict)
            with open(data_json_file, "w+") as f:
                f.write(json.dumps(data_dict))
        else:
            log_error_coverage_dict = self.extract_maxim_log()
            log_error_coverage_dict.update(crash_log_dict)
            # 如果appetize解析错误（网络等原因），这里仅提取dzh自身log_error 和maxim_log中的覆盖率
            with open(data_json_file, "w+") as f:
                f.write(json.dumps(log_error_coverage_dict))

    def extract_maxim_log(self):
        maxim_log_file = "{}/data/maximlog/max.activity.statistics.log".format(self.ext_path)
        maxim_log_dict = {"statistics": {"act_coverage": {"all": [], "covered": []}}}
        if os.path.exists(maxim_log_file):
            with open(maxim_log_file, "r", encoding='utf-8') as f:
                for i in f:
                    act_coverage = json.loads(i).get("TotalActivity")
                    act_covered = json.loads(i).get("TestedActivity")
            maxim_log_dict["statistics"]["act_coverage"]["all"] = act_coverage
            maxim_log_dict["statistics"]["act_coverage"]["covered"] = act_covered
        return maxim_log_dict


if __name__ == '__main__':
    dj = DataJsonUpdate()
    # dj.update_data_json_file("111")
    # crash_log_dict = {"log_error": []}
    # dj.update_data_json_file(crash_log_dict)
    # print(json.dumps(dj.extract_maxim_log()))
    crash_log_dict_1 = {"log_error": ["111","111"]}
    print(type(crash_log_dict_1))
    data_json_dict = dj.extract_maxim_log()
    print(type(data_json_dict))
    print(data_json_dict.update(crash_log_dict_1))
    with open('{}/data.json'.format(os.getcwd()), "w+") as f:
        f.write(json.dumps(data_json_dict))
