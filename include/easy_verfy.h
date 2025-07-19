//
// Created by root on 7/19/25.
//

#ifndef SEAV3_EASY_VERFY_H
#define SEAV3_EASY_VERFY_H
#include <functional>
#include <iostream>
#include <obfuscate.h>
#include <unordered_map>

std::string verify_host = OBFUSCATE("https://www.easyverify.top/api");// 域名

std::string verify_project_id = OBFUSCATE("10018");                                                               // 程序PID
std::string verify_project_key = OBFUSCATE("KWN1KBXDE9FA");                                                       //程序密钥
std::string verify_project_base64 = OBFUSCATE("UCPm8YnZsldF1pwVyhoKu3MkAJW2cDREfLSgxqT/iHabN0Qt5z6Ivj4B+OeGX7r9");// base64自定义编码集

std::string verify_project_public_key = OBFUSCATE("");

std::string verify_notice_link = OBFUSCATE("MISZX3JLIWZ1");// 获取公告的链接
std::string verify_notice_code = OBFUSCATE("200");         // 获取公告的code

std::string verify_update_link = OBFUSCATE("EH7K9I01FTMJ");// 更新链接
std::string verify_update_version = OBFUSCATE("100");      // 版本号
std::string verify_update_code = OBFUSCATE("200");         // 更新返回code

std::string verify_bind_link = OBFUSCATE("XK28IPSO66A8");// 绑定链接
std::string verify_bind_code = OBFUSCATE("200");         // 绑定返回code

std::string verify_unbind_link = OBFUSCATE("SL19ZU9K9IKE");// 解绑/换绑链接 返回数据无加密 无需设置code

std::string verify_variable_link = OBFUSCATE("9OBL5CHT35OP");// 变量链接
std::string verify_variable_code = OBFUSCATE("200");         // 变量返回code

std::string verify_heart_link = OBFUSCATE("QRL5NK61OO50") ;// 心跳验证 返回数据无加密 无需设置code

std::string verify_heart_code = OBFUSCATE("200");// 心跳返回code



std::string main_method_name = OBFUSCATE("main"); // 主方法
std::unordered_map<std::string ,std::function<void()>> method_map;

int verify_encryption = 1;// 默认1 base64 自定义编码集 2 rsa非对称加密
#endif //SEAV3_EASY_VERFY_H
