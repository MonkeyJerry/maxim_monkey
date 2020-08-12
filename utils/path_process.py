import logging
import os


class PathProcess:
    THIS_FILE_PATH = os.path.dirname(os.path.realpath(__file__))
    THIS_FILE_PATH_EXT = os.path.dirname(THIS_FILE_PATH)

    def data_path(self, *filename):
        try:
            for i in filename:
                if not isinstance(i, str):
                    raise ValueError("all filename should only be string types. Got {} {}".format(type(i), i))
            return os.path.join(self.THIS_FILE_PATH_EXT, *filename)
        except ValueError as e:
            logging.warning(e)

    @staticmethod
    def get_path_end_name(path):
        if r'/' in path:
            return path.split('/')[-1]
        return None

    @staticmethod
    def get_path_file(path):
        for _, _, files in os.walk(path):
            return files


if __name__ == '__main__':
    pp = PathProcess()
    # print(pp.THIS_FILE_PATH, pp.THIS_FILE_PATH_EXT)
    print(pp.get_path_file(r"D:\phpstudy_pro\WWW\testreport\test_apk_appetizer"))
