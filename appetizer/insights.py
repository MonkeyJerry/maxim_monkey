#!/usr/bin/env python3
#
# Copyright 2017 AppetizerIO (https://appetizer.io) 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import math
import random
import sys
import subprocess
import shutil
import time
import zipfile
import os
import codecs
import gzip
import json

from faker import Faker

from utils.path_process import PathProcess

try:
    import requests
    # kill it for now
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print('please install dependencies from requirements.txt')
    sys.exit(1)

try:
    import zlib

    COMPRESS = zipfile.ZIP_DEFLATED
except ImportError:
    print('python zlib is not available, which is highly suggested')
    COMPRESS = zipfile.STORED

CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config.json')
with open(CONFIG_PATH, 'r') as f:
    CONFIG = json.loads(f.read())

ANXIETY = CONFIG['anxiety']
TOKEN_PATH = os.path.join(os.path.dirname(__file__), '.access_token')
USERINFO_PATH = os.path.join(os.path.dirname(__file__), 'user_info.json')
with open(USERINFO_PATH, 'r') as f:
    USER_CONFIG = json.loads(f.read())
APKDUMP = os.path.join(os.path.dirname(__file__), 'apkdump.js')
OLD_DEVICE_LOG_BASE = "/sdcard/io.appetizer/"
try:
    subprocess.check_output(['node', '-v']);
except:
    print('Node.js is not installed and some functionality might not work properly')


def version(args):
    print('1.4.6')


def get_apk_manifest(apk):
    return subprocess.check_output(['node', APKDUMP, apk]).decode('utf-8')


def get_device_log_location(pkg, d=None):
    EXTERNAL_STORAGE = adb(['shell', 'echo', '$EXTERNAL_STORAGE'], d).decode('utf-8').strip()
    NEW_DEVICE_LOG_BASE = '%s/Android/data/%s/files/io.appetizer/' % (EXTERNAL_STORAGE, pkg,)
    if 'x_x' in adb(['shell', '[', '-d', NEW_DEVICE_LOG_BASE, ']', '||', 'echo', 'x_x'], d).decode('utf-8'):
        log_base = OLD_DEVICE_LOG_BASE
    else:
        log_base = NEW_DEVICE_LOG_BASE
        print('new log location is available: ' + log_base)
    return log_base + pkg + '.log'


def get_apk_package(apk):
    manifest = get_apk_manifest(apk)
    return json.loads(manifest)['package']


def adb(cmd, d=None, showCmd=False):
    dselector = [] if d is None else ['-s', d]
    fullCmd = ['adb'] + dselector + cmd
    if showCmd: print(fullCmd)
    return subprocess.check_output(fullCmd)  # 用这个函数导包后有问题，待分析改写成adb_android


def adb_android(cmd, d=None, showCmd=False, stdout=None, universal_newlines=False):
    dselector = '' if d is None else '-s {}'.format(d)
    fullCmd = 'adb ' + dselector + cmd
    if showCmd: print(fullCmd)
    return subprocess.Popen(fullCmd, stdout=stdout, universal_newlines=universal_newlines, shell=True)


def installed_check(apk):
    pkg = get_apk_package(apk)
    installed_pkg_list = adb_android("shell pm list packages", stdout=subprocess.PIPE, universal_newlines=True)
    for installed_item in installed_pkg_list.stdout:
        if pkg in installed_item:
            return True
    return False


def uninstall_android(apk, showCmd=False):
    wait_time = 0
    pkg = get_apk_package(apk)
    if installed_check(apk):
        adb_android("uninstall {}".format(pkg), showCmd=showCmd)
        print("uninstall start...")
    while installed_check(apk) and wait_time != 60:
        time.sleep(5)
        wait_time += 5
    print("uninstall success")
    time.sleep(10)  # 受手机性能影响


def install_android(apk, showCmd=False):
    wait_time = 0
    if not installed_check(apk):
        adb_android("install {}".format(apk), showCmd=showCmd)
        print("install start....")
    while not installed_check(apk) and wait_time != 60:
        time.sleep(5)
        wait_time += 5
    print("install success")
    time.sleep(15)  # 等待app在手机桌面显示，受手机性能影响


def _apkinfo(apk):
    valid, instrumented, packer, hasPerm, multiproc, pkg = False, False, None, False, False, None
    try:
        manifest = json.loads(get_apk_manifest(apk))
        valid = True
        pkg = manifest['package']
    except:
        return valid, instrumented, packer, hasPerm, multiproc, pkg
    with zipfile.ZipFile(apk) as checkf:
        try:
            checkf.getinfo('assets/appetizer.cfg')
            instrumented = True
        except:
            pass
    packer = is_fortified(apk)
    permissions = [p['name'] for p in manifest['usesPermissions']]
    hasPerm = 'android.permission.WRITE_EXTERNAL_STORAGE' in permissions
    components = manifest['application']['activities'] + manifest['application']['services'] + manifest['application'][
        'receivers']
    processes = list(set([p['process'] for p in components if 'process' in p]))
    multiproc = len(processes) > 1
    return valid, instrumented, packer, hasPerm, multiproc, pkg


def apkinfo(args):
    valid, instrumented, packer, hasPerm, multiproc, pkg = _apkinfo(args)
    if not valid:
        print('not a valid APK')
        return False
    print('pkg: %s' % (pkg,))
    if instrumented:
        print('input APK is already instrumented')
        return False
    if packer is not None:
        print("the apk is fortified by %s" % (packer,))
        return False
    if not hasPerm:
        print(
            "WARNING: the apk does not have READ/WRITE external storage permission. You will fail to use insights.py to analyze log on Android<=4.4 (Kitkat)")
    if multiproc:
        print(
            "WARNING: the apk launches multiple processes. multi-process support is not complete and could be problematic with Appetizer")
    return True


def _load_token():
    access_token = ''
    try:
        with open(TOKEN_PATH, 'r') as tokenfile:
            access_token = tokenfile.readline()
            if access_token == '':
                print('no stored access token, please login')
                return None
    except:
        print('no stored access token, please login')
        return None
    authorization = 'Bearer ' + access_token
    r = requests.get(CONFIG['check_token'], headers={'Authorization': authorization}, verify=False)
    if r.status_code != 200:
        print(r.json())
        print('stored access token is no longer valid, please login again')
        print('login by username and password now...')
        access_token = login()
        print("re-login and create new access token success.....")
    print('valid access token')
    print("access_token:" + access_token)
    return access_token


def apikey(apikey):
    access_token = apikey
    authorization = 'Bearer ' + access_token
    r = requests.get(CONFIG['check_token'], headers={'Authorization': authorization}, verify=False)
    if r.status_code != 200:
        print(r.json())
        print('invalid apikey')
    else:
        print('valid apikey')
        with open(TOKEN_PATH, 'w') as tokenfile:
            tokenfile.write(access_token)


def deployment(args):
    if args.private is None:
        API_BASE = 'https://api.appetizer.io/v2'
        CONFIG = {
            "anxiety": ANXIETY,
            "check_token": API_BASE + '/oauth/check_token',
            "get_token": API_BASE + '/oauth/access_token',
            "upload_server": 'http://upload.qiniu.com',
            "file_server": "",
            "request_instrumentation": API_BASE + '/insight/process/qiniu',
            "check_instrumentation": API_BASE + '/insight/process',
            "request_analysis": API_BASE + '/insight/analyze/qiniu',
            "check_analysis": API_BASE + '/insight/analyze',
        }
    else:
        try:
            if 'Appetizer' not in requests.get(args.private).text:
                raise Exception()
        except:
            print("Invalid AppetizerIO private deployment URL")
            return
        CONFIG = {
            "anxiety": ANXIETY,
            "check_token": args.private + '/pd/login_check',
            "get_token": None,
            "upload_server": args.private,
            "file_server": args.private,
            "request_instrumentation": args.private + '/v2/insight/process/local',
            "check_instrumentation": args.private + '/v2/insight/process',
            "request_analysis": args.private + '/v2/insight/analyze/local',
            "check_analysis": args.private + '/v2/insight/analyze',
        }
    with open(CONFIG_PATH, 'w') as f:
        f.write(json.dumps(CONFIG, sort_keys=True))
    print('Using %s deployment' % ('public' if args.private is None else 'private'))
    print('Please continue to login or set apikey')


def fake_login_info():
    fake = Faker()
    fake_email = fake.email()
    fake_username = fake.name().replace(" ", "")
    fake_password = fake_email.split("@")[0] + str(math.floor(1e3 * random.random()))
    fake_ua = fake.user_agent()
    print(fake_username, fake_email, fake_password, fake_ua)


def register():
    fake = Faker()
    fake_email = fake.email()
    fake_username = fake.name().replace(" ", "")
    fake_password = fake_email.split("@")[0] + str(math.floor(1e3 * random.random()))
    fake_ua = fake.user_agent()
    data = {"email": fake_email, "password": fake_password, "name": fake_username, "company": ""}
    headers = {'Content-Type': 'application/json', 'User-Agent': fake_ua}
    print(fake_email, fake_username, fake_password)
    print(CONFIG['signup'])
    r = requests.post(CONFIG['signup'], data=json.dumps(data), headers=headers, verify=False)
    if r.status_code != 200:
        print('Failed to register.')
        return False
    else:
        # access_token = r.json()['access_token']
        with open(USERINFO_PATH, 'w') as user_info_file:
            user_info_file.write(json.dumps(data))
        print('Register succeeded')
        return True


def login():
    if CONFIG['get_token'] is None:
        print('Login is not available for this deployment, please set apikey directly')
        return
    r = requests.post(CONFIG['get_token'],
                      data={
                          'grant_type': 'password',
                          'username': USER_CONFIG["name"],
                          'password': USER_CONFIG["password"]
                      }, headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic YXBwZXRpemVyX2NsaWVudDppbnRlcm5hbA=='
        }, verify=False)
    if r.status_code != 200:
        print('Failed to login. User does not exist or bad password')
        return False
    access_token = r.json()['access_token']
    with open(TOKEN_PATH, 'w') as tokenfile:
        tokenfile.write(access_token)
    print('Login succeeded')
    print('access token: ' + access_token)
    print('access token persisted, subsequent commands will be properly authenticated with this token')
    print('token will be valid for the following 60 days and will get renewed if any command is executed')
    return access_token


def logout(args):
    try:
        with open(TOKEN_PATH, 'w') as tokenfile:
            tokenfile.write('')
    except:
        pass
    print('Bye')


def is_fortified(apk, *args, **kwargs):
    with zipfile.ZipFile(apk) as zip_obj:
        solist = [s.rsplit('/')[-1] for s in zip_obj.namelist() if s.endswith('.so')]
    packer = None
    if 'libexecmain.so' in solist and 'libexec.so' in solist:
        packer = 'aijiami'
    elif 'libDexHelper.so' in solist and 'libDexHelper-x86.so' in solist:
        packer = 'bangbang enterprise'
    elif 'libsecmain.so' in solist and 'libsecexe.so' in solist:
        packer = 'bangbang'
    elif 'libtup.so' in solist or 'libexec.so' in solist:
        packer = 'tencent'
    elif ('libprotectClass.so' in solist and 'libprotectClass_x86.so' in solist) or (
            'libjiagu.so' in solist and 'libjiagu_art.so' in solist) or (
            'libjiagu.so' in solist and 'libjiagu_x86.so' in solist):
        packer = '360'
    elif 'libbaiduprotect.so' in solist and 'ibbaiduprotect_x86.so' in solist:
        packer = 'baidu'
    elif ('libddog.so' in solist and 'libfdog.so' in solist) or 'libchaosvmp.so' in solist:
        packer = 'najia'
    elif 'libnqshieldx86.so' in solist and 'libnqshield.so' in solist:
        packer = 'netqin'
    elif 'libmobisec.so' in solist or 'libmobisecx.so' in solist:
        packer = 'alibaba'
    elif 'libegis.so' in solist:
        packer = 'tongfudun'
    elif 'libAPKProtect.so' in solist:
        packer = 'apkprotect'
    elif any('libshell' in s for s in solist):
        packer = 'tencent_legu'
    return packer


def process(args, floating_menu=''):
    access_token = _load_token()
    if access_token is None:
        print('Please login to AppetizerIO first')
        return False
    # validate APK file
    if not apkinfo(args): return False
    valid, instrumented, packer, hasPerm, multiproc, pkg = _apkinfo(args)

    authorization = 'Bearer ' + access_token
    print(access_token)
    original_name = os.path.basename(args)
    token = None
    print('0. request Appetizer Insights upload permission')

    # floating_menu = '--enable-inapp-menu'
    appetizercfg = {"appetizercfg": {"floating_menu": floating_menu}}
    r = requests.post(CONFIG['request_instrumentation'], headers={'Authorization': authorization}, verify=False,
                      json=appetizercfg)
    r_json = r.json()
    if r.status_code != 200:
        print(r_json['message'])
        return False
    token = r_json['token']
    key = r_json['key']

    print('1. upload APK file')
    # print('apk: ' + apk)
    print('pkg: ' + pkg)
    print('upload......')
    with open(args, 'rb') as f:
        suffix = r_json['uploadUrl'] if 'uploadUrl' in r_json else ''
        ret = requests.post(CONFIG['upload_server'] + suffix, files={'file': f},
                            data={'key': key, 'token': token}).json()
    print(ret)
    if ret is None or 'success' not in ret or not ret['success']:
        print('upload error')
        return False

    print('2. wait for the APK to be processed')
    r_json = None
    while True:
        r = requests.get(CONFIG['check_instrumentation'], headers={'Authorization': authorization}, params={'key': key})
        r_json = r.json()
        if r_json['success'] != True:
            print(r_json)
            return False
        if r_json['state'] == 'return_upload_auth' or r_json['state'] == 'upload_finish' or r_json[
            'state'] == 'server_download':
            print('waiting...... server is downloading the APK')
        elif r_json['state'] == 'rewriting':
            print('waiting...... server is processing the APK')
        elif r_json['state'] == 'rewrite_success' or r_json['state'] == 'server_upload':
            print('waiting...... server is uploading the processed APK')
        elif r_json['state'] == 'server_upload_success':
            print('server has completed processing the APK')
            break
        else:
            print(r_json)
            print('server fails to process the APK')
            return False
        time.sleep(ANXIETY)
    print(r_json)
    downloadURL = r_json['downloadURL']
    print(downloadURL)

    print('3. download processed APK')
    if (downloadURL.startswith('http')):
        r = requests.get(downloadURL, stream=True)
    else:
        r = requests.get(CONFIG['file_server'] + downloadURL, stream=True)
    if r.status_code != 200:
        print('download failed')
        return False
    print('download completed')

    # 下载插桩包到指定目录下指定文件
    with open("{}/test_apk_appetizer/dzh_debug_appetizer.apk".format(PathProcess().THIS_FILE_PATH_EXT), "wb") as f:
        for chunk in r.iter_content(chunk_size=1024000):
            if chunk:
                f.write(chunk)
    return True


def install(args):
    try:
        adb(['version'])
    except:
        print('adb not available')
        return 1
    pkg = get_apk_package(args.apk)
    serialnos = args.serialnos if len(args.serialnos) > 0 else [None]
    print('1. install processed APK')
    for d in serialnos:
        adb(['uninstall', pkg], d)
        adb(['install', args.apk], d)  # Note: Xiaomi will pop up a dialog
    print('APK installed')

    print('2. grant permissions for logging')
    for d in serialnos:
        adb(['shell', 'pm', 'grant', pkg, 'android.permission.WRITE_EXTERNAL_STORAGE'], d, True)
        adb(['shell', 'pm', 'grant', pkg, 'android.permission.READ_EXTERNAL_STORAGE'], d, True)
    print('permission granted with adb, please double check')


def analyze(args, serialno='', clear=True):
    try:
        adb(['version'])
    except:
        print('adb not available')
        return False
    access_token = _load_token()
    if access_token is None:
        print('Please login to AppetizerIO first')
        return False
    authorization = 'Bearer ' + access_token
    # pkg = get_apk_package(args.apk)
    pkg = get_apk_package(args)
    with open('AndroidManifest.json', 'wb') as f:
        # f.write(get_apk_manifest(args.apk).encode('utf-8'))
        f.write(get_apk_manifest(args).encode('utf-8'))
    log_zip = pkg + '.log.zip'
    # d = args.serialno
    d = serialno
    DEVICE_LOG = get_device_log_location(pkg, d)
    fname = d if d is not None else "devicelog"
    fname += '.log'
    print('0. harvest and compress device logs')
    try:
        adb(['pull', DEVICE_LOG, fname], d)
    except:
        print(
            'failed to retrieve logs from a device, please double check if the app has the permission to log to SDCARD')
        return False
    with zipfile.ZipFile(log_zip, 'w') as myzip:
        myzip.write('AndroidManifest.json', compress_type=COMPRESS)
        myzip.write(fname)
    os.remove('AndroidManifest.json')
    os.remove(fname)

    print('1. request analysis from the server')
    r = requests.post(CONFIG['request_analysis'], headers={'Authorization': authorization}, data={'pkgName': pkg},
                      verify=False)
    if r.status_code != 200:
        print(r.status_code)
        print(r)
        return False
    r_json = r.json()
    print(r_json)
    token, key = r_json['token'], r_json['key']

    print('2. upload log file %s, with pkg: %s' % (log_zip, pkg))
    print('uploading......')
    with open(log_zip, 'rb') as f:
        suffix = r_json['uploadUrl'] if 'uploadUrl' in r_json else ''
        ret = requests.post(CONFIG['upload_server'] + suffix, files={'file': f},
                            data={'key': key, 'token': token}).json()
        print(ret)
        print("upload success")
    if ret is None or 'success' not in ret or not ret['success']:
        print('upload error')
        return 1

    print('3. server analyzing')
    r_json = None
    downloadURL = ''
    try_times = 0
    while True:
        print("start analyze")
        # print(CONFIG['check_analysis'], {'Authorization': authorization}, {'key': key})
        r = requests.get(CONFIG['check_analysis'], headers={'Authorization': authorization}, params={'key': key})
        # print(r.json())
        r_json = r.json()
        if r_json['success'] != True:
            print(r_json)
            return 1
        if r_json['state'] == 'return_upload_auth' or r_json['state'] == 'upload_finish' or r_json[
            'state'] == 'server_download':
            print('waiting...... server is downloading log')
        elif r_json['state'] == 'analyzing':
            print('waiting...... server is analyzing')
        elif r_json['state'] == 'analyze_success' or r_json['state'] == 'report_exporting':
            print('waiting...... server is exporting the report')
        elif r_json['state'] == 'report_export_success' or r_json['state'] == 'server_upload':
            print('waiting...... server is uploading the generated report')
        elif r_json['state'] == 'server_upload_success':
            print('server has generated and uploaded the report')
            if 'downloadURL' in r_json:
                print('download report data at:')
                downloadURL = r_json['downloadURL']
                print('3. download analyzed json data')
                if (downloadURL.startswith('http')):
                    print(downloadURL)
                else:
                    print(CONFIG['file_server'] + downloadURL)
            break
        else:
            print(r_json)
            print('server fails to analyze the logs')
            try_times += 1
            time.sleep(ANXIETY)
            if try_times == 3:
                return False
        time.sleep(ANXIETY)

    print('4. cleanup')
    os.remove(log_zip)
    if clear:
        clearlog(args)
    else:
        print('Please remember to run clearlog command before next test')
    print('All done! You can now view the report via Appetizer Desktop')
    return downloadURL


def clearlog(args, serialno=''):
    pkg = get_apk_package(args)
    DEVICE_LOG = get_device_log_location(pkg, serialno)
    adb(['shell', '>' + DEVICE_LOG], serialno)
    print('done')


def main():
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(help='all supported commands')

    login_parser = subparsers.add_parser('login', help='login to AppetizerIO and cache the access token')
    login_parser.add_argument('username', action='store',
                              help='AppetizerIO account username, register at https://appetizer.io/')
    login_parser.add_argument('password', action='store', help='AppetizerIO account password')
    login_parser.set_defaults(func=login)

    logout_parser = subparsers.add_parser('logout', help='logout from AppetizerIO')
    logout_parser.set_defaults(func=logout)

    apikey_parser = subparsers.add_parser('apikey', help='set access token to use AppetizerIO for DevOps')
    apikey_parser.add_argument('apikey', action='store',
                               help='AppetizerIO account apikey, obtained from user profile in the GUI')
    apikey_parser.set_defaults(func=apikey)

    deployment_parser = subparsers.add_parser('deployment', help='set public/private deployment for AppetizerIO')
    deployment_parser.add_argument('--private', action='store', default=None, help='AppetizerIO private deployment URL')
    deployment_parser.set_defaults(func=deployment)

    apkinfo_parser = subparsers.add_parser('apkinfo',
                                           help='display the basic information of an APK and check if it is ready for Appetizer')
    apkinfo_parser.add_argument('apk', action='store', help='the path to the APK file')
    apkinfo_parser.set_defaults(func=apkinfo)

    process_parser = subparsers.add_parser('process', help='upload an APK for instrumentation')
    process_parser.add_argument('apk', action='store', help='the path to the APK file')
    process_parser.add_argument('processed_apk', action='store', help='the complete path to save the instrumented APK')
    process_parser.add_argument('--enable-inapp-menu', action='store_true', help='enable the in-app Appetizer menu',
                                default=False, dest='floating_menu')
    process_parser.set_defaults(func=process)

    analyze_parser = subparsers.add_parser('analyze',
                                           help='fetch and analyze device logs and generate diagnosis report')
    analyze_parser.add_argument('apk', action='store', help='the path to the processed APK file')
    analyze_parser.add_argument('-s', dest='serialno', default=None, action='store',
                                help='device serial number, see adb devices output')
    analyze_parser.add_argument('--clear', action='store_true', default=False,
                                help='delete the logs from the devices after the analysis')
    analyze_parser.set_defaults(func=analyze)

    clearlog_parser = subparsers.add_parser('clearlog',
                                            help='delete the logs generated by a particular APK on the devices')
    clearlog_parser.add_argument('apk', action='store', help='the path to the processed APK file')
    clearlog_parser.add_argument('-s', dest='serialno', default=None, action='store',
                                 help='device serial number, see adb devices output')
    clearlog_parser.set_defaults(func=clearlog)

    install_parser = subparsers.add_parser('install', help='install processed APK and grant necessary permissions')
    install_parser.add_argument('apk', action='store', help='the path to the processed APK file')
    install_parser.add_argument('-s', '--serialno', dest='serialnos', default=[], action='append',
                                help='device serial number, see adb devices output')
    install_parser.set_defaults(func=install)

    version_parser = subparsers.add_parser('version', help='print version and exit')
    version_parser.set_defaults(func=version)

    args = parser.parse_args()
    if 'func' not in args:
        parser.print_help()
        return 1
    return args.func(args)


# if __name__ == '__main__':
#     sys.exit(main())
# else:
#     print("this script is intended as a CLI not a package yet")

if __name__ == '__main__':
    # print(apikey("e7e9a8ccbda824c212f4287fbf53d092d98a785"))
    # path = PathProcess()
    # ext_path = path.THIS_FILE_PATH_EXT
    # apk_path = "{}/test_apk_appetizer".format(ext_path)
    # gz_path = "{}/data".format(ext_path)
    #
    # apk = path.get_path_file(apk_path)[0]
    # test_apk_appetizer = "{0}/test_apk_appetizer/{1}".format(ext_path, apk)
    # # analyze(test_apk_appetizer)
    # process(test_apk_appetizer)
    # https://api.appetizer.io/v2/insight/analyze {'Authorization': 'Bearer 89456c587c55d0819a848b40ab16c22ba294cb0d'} {'key': '5ece1784f67eac5288949197'}
    # r = requests.get("https://api.appetizer.io/v2/insight/analyze", headers={'Authorization': "Bearer 89456c587c55d0819a848b40ab16c22ba294cb0d"}, params={'key': '5ece1784f67eac5288949197'})
    # print(r)
    pass
