#!/usr/bin/python
# -*- coding:utf-8 -*- 


import sys,os
from lxml import etree
import sqlite3
import unicodecsv as ucsv

host = ''
result_list = []
file_path = []


def htm_parse(l):
    if b'#d43f3a' in etree.tostring(l):
        info = u"严重 - " + l.text
    elif b'#ee9336' in etree.tostring(l):
        info = u"高危 - " + l.text
    elif b'#fdc431' in etree.tostring(l):
        info = u"中危 - " + l.text
    elif b'#3fae49' in etree.tostring(l):
        info = u"低危 - " + l.text
    elif b'#0071b9' in etree.tostring(l):
        info = u'信息泄露 - ' + l.text
    else:
        info = 'Parsing error,Check that the versions are consistent.'
    return info


def main(filename):
    html = etree.parse(filename, etree.HTMLParser())
    ls = html.xpath('/html/body/div[1]/div[3]/div')
    # print(ls)
    for i in ls:
        # print(i.text)
        if b"font-size: 22px; font-weight: bold; padding: 10px 0;" in etree.tostring(i):
            host = i.text
            # print(host)
        elif b"this.style.cursor='pointer'" in etree.tostring(i):
            result = host + " - " + htm_parse(i)
            # print(result)
            result_list.append(result)
    return result_list


def select(ip, id):
    conn = sqlite3.connect('vuln.db')
    conn.text_factory = lambda x: str(x, 'gbk', 'ignore')
    # conn.text_factory=str
    cursor = conn.cursor()
    for row in cursor.execute("select * from VULNDB where Plugin_ID=?", (id,)):
        # print(id)
        return [ip, row[1], row[2], row[3], row[4]]


if __name__ == '__main__':
    filepath = sys.argv[1]
    if os.path.isfile(filepath):
        file_path.append(filepath)
    else:
        dirpath = os.listdir(filepath)
        for s in dirpath:
            if os.path.isfile((filepath+'/').replace('//','/')+s):
                file_path.append((filepath+'/').replace('//','/')+s)
            else:
                continue
        for file in file_path:
            list_host = main(file)
            with open('{}.csv'.format(file), 'wb') as f:
                w = ucsv.writer(f, encoding='gbk')
                title = [u'服务器IP', u'漏洞名称', u'风险级别', u'漏洞描述', u'修复建议']
                w.writerow(title)
                for i in list_host:
                    info = i.split('-', 3)
                    # print(info[0],info[2])
                    result = select(info[0], info[2])
                    if result is not None:
                        data = result
                    else:
                        data = info[0], info[3], info[1]
                    w.writerow(data)




