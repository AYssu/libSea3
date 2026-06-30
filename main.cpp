#include "http.h"
#include "smemory.h"
#include "smmap.h"
#include "sutils.h"
#include "easy_verfy.h"
#include "driver/driver_syscall.h"
#include "verify.h"
#include <iomanip>
#include <atomic>
#include <chrono>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <thread>
// 需要引用这个 因为配置文件只需要引用一次
#include "json.hpp"

static const char *ws_reason_to_zh_local(const std::string &reason) {
    // 同 network/verify.cpp 的 ws_reason_to_zh(reason)
    if (reason == "MEMBER_EXPIRED") return "会员未开通或已过期";
    if (reason == "AUTH_FAIL") return "用户名或密码错误";
    if (reason == "BAD_APPSIG") return "应用签名校验失败";
    if (reason == "APP_MISMATCH") return "应用标识不匹配";
    if (reason == "EXPIRED") return "请求时间已过期";
    if (reason == "REPLAY") return "请求重复(重放保护触发)";
    if (reason == "BAD_SEQ") return "请求序号无效";
    if (reason == "BAD_DEVICE") return "设备信息缺失或格式不合法";
    if (reason == "DEVICE_BANNED") return "设备已被封禁";
    if (reason == "DEVICE_CONFLICT") return "设备冲突，不允许绑定";
    if (reason == "BIND_FAIL") return "设备绑定失败";
    if (reason == "LOGIN_ELSEWHERE") return "账号在其他设备登录，本连接被挤下线";
    if (reason == "NO_HELLO") return "缺少HELLO握手上下文";
    if (reason == "BAD_PUBKEY") return "客户端公钥无效";
    if (reason == "MISSING_CIPHER") return "缺少加密载荷";
    if (reason == "DECRYPT_FAIL") return "AUTH解密失败";
    if (reason == "ALREADY_AUTHED") return "连接已鉴权，不能重复认证";
    if (reason == "APP_INVALID") return "应用无效或已禁用";
    if (reason == "AUTH_INVALID") return "认证状态无效，请重新登录";
    if (reason == "MISSING_FIELDS") return "请求字段缺失";
    if (reason == "UNSUPPORTED") return "不支持的消息类型";
    if (reason == "BAD_JSON") return "消息不是合法JSON";
    if (reason == "MISSING_TYPE") return "缺少消息类型字段";
    return "";
}

static std::string ws_extract_reason(const std::string &err) {
    // 兼容形如 "... reason=MEMBER_EXPIRED" 或 "... [MEMBER_EXPIRED]"
    if (err.empty()) return {};
    const std::string key = "reason=";
    auto p = err.find(key);
    if (p != std::string::npos) {
        p += key.size();
        size_t e = err.find_first_of("] \r\n\t", p);
        if (e == std::string::npos) e = err.size();
        return err.substr(p, e - p);
    }
    auto lb = err.rfind('[');
    auto rb = err.rfind(']');
    if (lb != std::string::npos && rb != std::string::npos && lb + 1 < rb) {
        return err.substr(lb + 1, rb - lb - 1);
    }
    return {};
}

static bool ws_reason_non_retryable(const std::string &err) {
    // 来自 network/verify.cpp 的 ws_reason_to_zh(reason) 列表：这些属于业务拒绝/参数问题，重试也不会成功
    static const char *kReasons[] = {
        "MEMBER_EXPIRED",
        "AUTH_FAIL",
        "BAD_APPSIG",
        "APP_MISMATCH",
        "EXPIRED",
        "REPLAY",
        "BAD_SEQ",
        "BAD_DEVICE",
        "DEVICE_BANNED",
        "DEVICE_CONFLICT",
        "BIND_FAIL",
        "LOGIN_ELSEWHERE",
        "NO_HELLO",
        "BAD_PUBKEY",
        "MISSING_CIPHER",
        "DECRYPT_FAIL",
        "ALREADY_AUTHED",
        "APP_INVALID",
        "AUTH_INVALID",
        "MISSING_FIELDS",
        "UNSUPPORTED",
        "BAD_JSON",
        "MISSING_TYPE",
    };
    for (const auto *r : kReasons) {
        if (!err.empty() && err.find(r) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string generate_uuid_v4() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;
    for (int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            ss << '-';
        } else if (i == 14) {
            ss << '4';// UUID version 4
        } else if (i == 19) {
            ss << "0123456789abcdef"[dis(gen) & 0x3 | 0x8];// variant 10x
        } else {
            ss << "0123456789abcdef"[dis(gen)];
        }
    }
    return ss.str();
}

int main(int argc, char *argv[]) {
    std::cout << "self -pid: " << syscall(__NR_getpid) << " -tid: " << syscall(__NR_gettid) << "\n";
    std::cout << "欢迎使用libSea4 多工具集成静态库" << std::endl;
    std::cout << "1、内存工具类" << std::endl;
    std::cout << "2、内存映射测试" << std::endl;
    std::cout << "3、网络请求" << std::endl;
    std::cout << "4、测试网络验证-公告" << std::endl;
    std::cout << "5、测试网络验证-更新" << std::endl;
    std::cout << "6、测试网络验证-变量" << std::endl;
    // 卡密绑定里面也有变量
    std::cout << "7、测试网络验证-卡密绑定" << std::endl;
    std::cout << "8、测试网络验证-卡密换绑" << std::endl;
    std::cout << "9、工具类测试" << std::endl;
    std::cout << "10、WebSocket本地测试(wscat)" << std::endl;
    std::cout << "11、测试网络验证-WS用户登录" << std::endl;
    std::cout << "12、测试网络验证-卡密WS心跳" << std::endl;


    auto test_num = custom_sutils::get_input_int("请输入调试的内容:");
    switch (test_num) {
        case 1: {
            static auto driver_mgr = new syscall_driver();
            auto read_flag = smemory::set_read<uintptr_t>([&](uintptr_t address, void *data, size_t size) -> long {
                return driver_mgr->read(address, data, size);
            });// 调用自定义读写 实现低耦合 理论支持全读写 即使未来出了什么无敌读写也能快速适配

            auto write_flag = smemory::set_write<uintptr_t>([&](uintptr_t address, void *data, size_t size) -> long {
                return driver_mgr->write(address, data, size);
            });

            // 设置完成 下次静态库调用的为编译的读写 小白啥也不用管 默认即可
            if (!read_flag || !write_flag) {
                std::cout << "设置自定义读写失败!" << std::endl;
                return 0;
            }

            auto pid = smemory::get_package_pid("gg.pointers");
            driver_mgr->set_pid(pid);
            std::cout << "进程ID:" << pid << std::endl;
            auto base = smemory::get_module_base_str("libgame.so", 1, "Xa");
            std::cout << "模块基址:" << std::hex << base << std::dec << std::endl;
            auto i = pointer::read_int(base);
            std::cout << "读取int:" << i << std::endl;
            auto f = pointer::read_float(base);
            std::cout << "读取float:" << f << std::endl;
            auto d = pointer::read_double(base);
            std::cout << "读取double:" << d << std::endl;
            auto w = pointer::read_word(base);
            std::cout << "读取word:" << w << std::endl;
            auto byte = pointer::read_char(base);
            std::cout << "读取char:" << byte << std::endl;
            auto q = pointer::read_qword(base);
            std::cout << "读取qword:" << q << std::endl;
            struct Vector3A {
                float x, y, z;
            };
            Vector3A v = {};
            smemory::readv(base, &v, sizeof(Vector3A));
            std::cout << "读取Vector3A:" << v.x << " " << v.y << " " << v.z << std::endl;
        } break;
        case 2: {
            struct demo {
                int x, y, z;
            };

            auto demo_ptr = new demo();// 内存映射需要地址 和长度
            demo_ptr = static_cast<demo *>(smmap::build_mmap_void("mmap_struct", false, sizeof(demo)));
            // 将结构体映射到内存中 当其他进程调用smmap::build_mmap_void("mmap_struct", false, sizeof(demo)); 即可实现共享内存
            demo_ptr->x++;
            demo_ptr->y++;
            demo_ptr->z++;
            std::cout << "结构体映射:" << demo_ptr->x << " " << demo_ptr->y << " " << demo_ptr->z << std::endl;
            munmap(demo_ptr, sizeof(demo));
            // 关闭映射 能干嘛?跨进程通信啊同学,配置文件也能使用,不香嘛
        } break;
        case 3: {
            auto http = shttp::http_get("https://www.easyverify.top");
            std::cout << "请求是否成功: " << http.success << std::endl;
            std::cout << "状态码: " << http.code << std::endl;
            std::cout << "响应数据: " << http.data << std::endl;
            std::cout << "错误信息: " << http.error << std::endl;
        } break;
        case 4: {
            std::cout << "-- 测试公告" << std::endl;
            sverify::verify_json json = {};// 清空结构体数据
            // NOLINTNEXTLINE
            sverify::get_notice(json);
            if (json.success) {
                std::cout << "获取到的公告: " << json.notice << std::endl;
                std::cout << "服务器时间戳:" << json.timestamp << std::endl;

            } else {
                std::cout << "获取公告失败: " << json.error_message << std::endl;
            }
            std::cout << "请求状态码: " << json.status_code << std::endl;

        } break;
        case 5: {
            sverify::verify_json json2 = {};// 清空结构体数据
            // NOLINTNEXTLINE
            sverify::get_update(json2);
            if (json2.success) {
                if (json2.have_update) {
                    std::cout << "是否强制更新: " << (json2.update_must ? "强制更新" : "不强制") << std::endl;
                    std::cout << "更新公告: " << json2.update_message << std::endl;
                    std::cout << "更新链接: " << json2.update_url << std::endl;
                } else {
                    std::cout << "当前最新版本，公告(更新增强): " << json2.notice << std::endl;
                }
            } else {
                std::cout << "获取更新失败: " << json2.error_message << std::endl;
            }
            std::cout << "请求状态码: " << json2.status_code << std::endl;

        } break;
        case 6: {
            std::cout << "-- 测试变量" << std::endl;
            sverify::verify_json json3 = {};// 清空结构体数据
            // NOLINTNEXTLINE
            sverify::get_variables(json3);
            if (json3.success) {
                std::cout << "获取到的变量: " << json3.variables << std::endl;
                std::cout << "服务器时间戳:" << json3.timestamp << std::endl;

            } else {
                std::cout << "获取变量失败: " << json3.error_message << std::endl;
            }
            std::cout << "请求状态码: " << json3.status_code << std::endl;
        } break;
        case 7: {
            std::cout << "-- 测试单码卡密绑定" << std::endl;
            sverify::verify_json json4 = {};// 清空结构体数据
            // NOLINTNEXTLINE
            sverify::bind_card("APLU6CU7A5KU2ZNT", sutils::get_imei(3), json4);
            if (json4.success) {
                std::cout << "卡密ID: " << json4.card_id << std::endl;
                std::cout << "到期时间: " << json4.end_time << std::endl;
                std::cout << "到期时间戳: " << json4.available << std::endl;
                std::cout << "卡密类型: " << json4.card_type << std::endl;
                std::cout << "绑定次数: " << json4.bind_number << std::endl;
                std::cout << "解绑次数: " << json4.unbind_number << std::endl;
                std::cout << "核心数据: " << json4.core << std::endl;
                std::cout << "程序变量: " << json4.variables << std::endl;
                std::cout << "心跳Token: " << json4.token << std::endl;

                // 测试心跳：40秒一次，循环10次
                if (!json4.token.empty()) {
                    std::string currentToken = json4.token;
                    for (int i = 1; i <= 10; i++) {
                        std::cout << "\n-- 心跳第 " << i << "/10 次 (间隔40s)" << std::endl;
                        sverify::verify_json hb = {};
                        sverify::card_heartbeat(currentToken, hb);
                        if (hb.success) {
                            std::cout << "心跳成功" << std::endl;
                            std::cout << "  新Token: " << hb.token << std::endl;
                            std::cout << "  剩余秒数: " << hb.available << std::endl;
                            std::cout << "  到期时间: " << hb.end_time << std::endl;
                            std::cout << "  卡密ID: " << hb.card_id << std::endl;
                            std::cout << "  程序变量: " << hb.variables << std::endl;
                            std::cout << "  服务器时间戳: " << hb.timestamp << std::endl;
                            std::cout << "  疑似多用户共用: " << (hb.potentially_shared ? "是" : "否") << std::endl;
                            currentToken = hb.token; // 用新 token 替换旧的
                        } else {
                            std::cout << "心跳失败: " << hb.error_message << std::endl;
                            break;
                        }
                        if (i < 10) {
                            std::cout << "等待40秒..." << std::endl;
                            std::this_thread::sleep_for(std::chrono::seconds(40));
                        }
                    }
                }
            } else {
                std::cout << "绑定卡密失败: " << json4.error_message << std::endl;
            }
            std::cout << "请求状态码: " << json4.status_code << std::endl;

        } break;
        case 8: {
            std::cout << "-- 测试单码卡密换绑" << std::endl;
            sverify::verify_json json5 = {};// 清空结构体数据
            // NOLINTNEXTLINE
            sverify::unbind_card("YY579ULTFC6K2X2B", sutils::get_imei(3), json5);
            if (json5.success) {
                std::cout << "换绑成功: 换绑成功" << std::endl;
            } else {
                std::cout << "换绑失败: " << json5.error_message << std::endl;
            }
            std::cout << "请求状态码: " << json5.status_code << std::endl;

        } break;
        case 9: {
            std::string str = "abc阿夜6哔";
            std::cout << "原字符串: " << str << std::endl;
            auto md5 = sutils::to_md5(str);
            std::cout << "默认小写 MD5: " << md5 << std::endl;
            md5 = sutils::to_md5(str, true);
            std::cout << "大写 MD5: " << md5 << std::endl;
            std::string b64_chars = "164pqrGF3bZwMfh/Ty29j7KHVnsxJDlX8EBegWC5+OzRuiNSmaPt0QLIkUYAdcov";
            std::string encoded = sutils::base64_encode(str, b64_chars);
            std::string decoded = sutils::base64_decode(encoded, b64_chars);

            std::cout << "自定义base64加密: " << encoded << std::endl;
            std::cout << "自定义base64解密: " << decoded << std::endl;

            auto hex = sutils::to_hex(str);
            std::cout << "默认小写 HEX: " << hex << std::endl;
            hex = sutils::to_hex(str, true);
            std::cout << "大写 HEX: " << hex << std::endl;

            std::cout << "当前时间戳: " << sutils::get_timestamp() << std::endl;

            auto sha = sutils::sha256(str);
            std::cout << "默认小写 sha256: " << sha << std::endl;
            sha = sutils::sha256(str, true);
            std::cout << "大写 sha256: " << sha << std::endl;

            std::string public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw0lDF9vj2o0KdiGeguV9fig+DCf+4WTf6hs5KDw7tFtqDFk9C6giFCP2K5SHNjH/PFYQ/Arn+ccBZwO/5wpz/HzKF41zgoF5gyEV1T1FoqjgC40HO7iXM1WO0ORTS4/T7U1obwHf42pfm4kjBkl/yzngPSdK7aBffI50kLc4gDlRQLffEP3ilKiEJ/HSOqtunadAXWUrnecn0CRdu+gZ1FlfLO7D1qcqaOl4dPtEgn/1tzr77fUMs7rElxaQvbV51R3HTuLz9HZfSg4ZNOqMzEx424T9XTvht0WKisTyhBd/xWUWevwYOMaarHDlJoqU/Hn04ALrrWpTeWAYW0rthQIDAQAB";
            std::string private_key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDSUMX2+PajQp2IZ6C5X1+KD4MJ/7hZN/qGzkoPDu0W2oMWT0LqCIUI/YrlIc2Mf88VhD8Cuf5xwFnA7/nCnP8fMoXjXOCgXmDIRXVPUWiqOALjQc7uJczVY7Q5FNLj9PtTWhvAd/jal+biSMGSX/LOeA9J0rtoF98jnSQtziAOVFAt98Q/eKUqIQn8dI6q26dp0BdZSud5yfQJF276BnUWV8s7sPWpypo6Xh0+0SCf/W3Ovvt9QyzusSXFpC9tXnVHcdO4vP0dl9KDhk06ozMTHjbhP1dO+G3RYqKxPKEF3/FZRZ6/Bg4xpqscOUmipT8efTgAuutalN5YBhbSu2FAgMBAAECggEABItvbXOMwBjOg1pGm0A7pT8gK93rFL6+u+7Ulob0Ur8FNEgICiiTBnShys4tlAl3fvrNHA3QQTlW4y6sqB6k/V1qweqPo3Ffl7l3jcYGbqx5w6W4Dd/pW49PAAstlGbCpVVLAWOsnK5sjteTAkHyoJL2ZiXvHKGXUfQ/aotrsVwu9rf1zAL8MRz0yHGJI7HYb8J/Agl2Es74yc8t8ZZ3QjQByDWR26AGi9nNNk8jP9lbCdcK1UElQ9FOFlUBnn7Hu5RMJH1PHaIhwKHMqQPGSqL3y9U6z7d7f3eAOMohZbL4GFcV2SRilzfYjpBjYl+wLUks7lwJqRypfl2yNPd4HwKBgQD9WzgboPMxWhnvgmCO3YFXotl/nLzXA0r5MaCC01trZCgzhAWKXrLf5vs6UIetJtSCg2JgYAJcNzGRrblOw8dywh8LC0/PwlNqOB0c2ZYRIEUEBi3aHIiVMBtwMUWu1g+U/nzckbfH1odYAmhxk6e2bAggA/BdZLrO3yv8QsSYKwKBgQDFUuwi5LTbylL0iMFsHOh+f3HkzpD7EP438ZQYGdtYW8gZPm9MPDDpieatzOMBlOrGyYb5qzaqZOKfizZha4aJmf9s7zXFV426uch8GB3ogo3xorqmGefT/es9PeHt2laBdG8spAuY7w5s+kZXTY1B0v6CfsC5rRcJOj7BioWJDwKBgDxOqlxpQ3pL6ECK2FEpiNBDg2JM/OZxcjc/COYbSXeWr7sTgf4d7JY/dS28XY9p3svyWkh2khlBShtTLvkAwUkfzCPk3Wqm5xQxpzxmzsHk3IjIr8FraVeZy+44zE2BxtPAgBhA125KMo1QhWwDqbhSntyAE4cnow/7L40sl39hAoGARZ4V9dGfBZSCZAgDxfMFC+xG8KT4fbvnFTHEQCSPQMNQ+6cNeWYbE6o1msgYpyw1EOF1H40Kgl+JnSRukTxwgQe2GGblH7TeKiz10OJpWukEz2XMWGH3atHBNyAoH9TShGXh+2v9M33UJxq9yntwBPM+HChAMsIgyH6mOX530n0CgYEA014CtMmpWVZau+etxm7lKAubC414o6XwZuNxodQo88M0LJxQMCeiUPEzq03Igcaf5qAGothqjlx2+7fEDvTgLuT6FRgUcXtmu8Fs7PWKVi/0g0mct3ctPn28WrlZ1NORo5YtFeGB44/yYoje7WdNpR0zWLTblhpC8bW8i98gXcA=";

            auto pub_key = sutils::pem_format(public_key, false);
            auto pri_key = sutils::pem_format(private_key, true);

            // 公钥加密-私钥解密
            auto encrypt_text = sutils::rsa_public_encrypt(str, pub_key);
            encrypt_text = sutils::base64_encode(encrypt_text);
            std::cout << "公钥加密: " << encrypt_text << std::endl;
            auto decrypt_text = sutils::rsa_private_decrypt(sutils::base64_decode(encrypt_text), pri_key);
            std::cout << "私钥解密: " << decrypt_text << std::endl;

            // 私钥加密-公钥解密
            encrypt_text = sutils::rsa_private_encrypt(str, pri_key);
            encrypt_text = sutils::base64_encode(encrypt_text);
            std::cout << "私钥加密: " << encrypt_text << std::endl;
            decrypt_text = sutils::rsa_public_decrypt(sutils::base64_decode(encrypt_text), pub_key);
            std::cout << "公钥解密: " << decrypt_text << std::endl;

            /**
            * get_imei(int,bool) int 1-3 log
            * 在Android设备su环境和普通环境的设备码会不一样
            * 如果没有特别需求你最好使用Java获取设备的imei
            * 这个imei为可执行文件设计(伪imei)
            */
            auto imei = sutils::get_imei();
            std::cout << "IMEI(默认md5): " << imei << std::endl;
            imei = sutils::get_imei(2);
            std::cout << "IMEI(开启sha256): " << imei << std::endl;
            imei = sutils::get_imei(3);
            std::cout << "IMEI(base64): " << imei << std::endl;


            std::string rc4_key = "abc123456";
            auto rc4_data = sutils::rc4_crypt(str, rc4_key);
            std::cout << "RC4 加密: " << rc4_data << std::endl;
            rc4_data = sutils::rc4_crypt(rc4_data, rc4_key);
            std::cout << "RC4 解密: " << rc4_data << std::endl;

            std::string key = "1234567890123456"; // 16字节密钥
            std::string plaintext = "Hello, AES Encryption!";
            
            // 加密
            std::string encrypted = sutils::aes128_encrypt(plaintext, key);
            std::cout << "Encrypted: " << encrypted << std::endl;
            
            // 解密
            std::string decrypted = sutils::aes128_decrypt(encrypted, key);
            std::cout << "Decrypted: " << decrypted << std::endl;
            
            auto format = sutils::format_local_datetime();
            std::cout << "格式化时间: " << format << std::endl;
           
        } break;
        case 10: {
            std::cout << "-- WebSocket本地测试" << std::endl;
            std::cout << "请先启动服务端: npx wscat -l 8787" << std::endl;

            auto client = shttp::ws_connect("ws://127.0.0.1:8787", true);
            if (!client) {
                std::cout << "连接失败: ws://127.0.0.1:8787" << std::endl;
                break;
            }
            std::cout << "连接成功: ws://127.0.0.1:8787" << std::endl;

            auto send_ret = shttp::ws_send(client, "hello from SeaV4", false, true);
            if (!send_ret.success) {
                std::cout << "发送失败: " << send_ret.error << std::endl;
                shttp::ws_close(client);
                break;
            }
            std::cout << "发送成功, 字节数: " << send_ret.sent << std::endl;

            auto recv_ret = shttp::ws_recv(client, 4096, true);
            if (!recv_ret.success) {
                std::cout << "接收失败: " << recv_ret.error << std::endl;
                shttp::ws_close(client);
                break;
            }
            std::cout << "接收成功: " << recv_ret.data << std::endl;
            std::cout << "frame flags: " << recv_ret.flags << " bytes_left: " << recv_ret.bytes_left << std::endl;

            shttp::ws_close(client);
            std::cout << "连接已关闭" << std::endl;
        } break;
        case 11: {
            std::cout << "-- 测试网络验证-WS用户登录(含后台断线重连)" << std::endl;
            const std::string username = "2997036064@qq.com";
            const std::string password = "admin666";
            std::atomic<bool> ws_demo_running{true};
            std::thread ws_reconnect_thread([&]() {
                while (ws_demo_running.load()) {
                    sverify::verify_json j{};
                    if (!sverify::user_ws_ensure_connected(username, password, j, false)) {
                        if (ws_reason_non_retryable(j.error_message)) {
                            const std::string reason = ws_extract_reason(j.error_message);
                            const std::string zh = ws_reason_to_zh_local(reason);
                            if (!reason.empty() && !zh.empty()) {
                                std::cout << "[ws] 不可重试，停止重连: " << reason << " (" << zh << ")" << std::endl;
                            } else {
                                std::cout << "[ws] 不可重试，停止重连: " << j.error_message << std::endl;
                            }
                            ws_demo_running.store(false);
                            break;
                        }
                        if (!ws_demo_running.load()) {
                            break;
                        }
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        continue;
                    }
                    if (!ws_demo_running.load()) {
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                }
            });

            std::cout << "后台重连线程已启动，等待首次 WS 就绪(最多约 30 秒)..." << std::endl;
            const auto ws_ready_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
            while (std::chrono::steady_clock::now() < ws_ready_deadline && !sverify::user_ws_connected()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            if (!sverify::user_ws_connected()) {
                ws_demo_running.store(false);
                ws_reconnect_thread.join();
                std::cout << "WS 在限时内未连上，请检查网络/账号密码" << std::endl;
                break;
            }

            std::cout << "WS 已连接，可调试；后台每 5 秒检查一次，掉线则约 2 秒后重试" << std::endl;
            std::cout << "连接保持中，等待HEARTBEAT变量推送..." << std::endl;
            std::cout << "0=退出WS 1=变量池数量 2=变量池(仅时间戳/序号) 3=变量池(含密文) 4=按当前时间回溯解密 5=WS连接是否存在" << std::endl;
            while (true) {
                int op = custom_sutils::get_input_int("请输入WS调试命令(0/1/2/3/4/5):");
                if (op == 0) {
                    ws_demo_running.store(false);
                    ws_reconnect_thread.join();
                    sverify::ws_user_disconnect(true);
                    std::cout << "WS会话已退出" << std::endl;
                    break;
                } else if (op == 1) {
                    std::cout << "变量池数量: " << sverify::ws_variable_pool_size() << std::endl;
                } else if (op == 2) {
                    std::cout << "变量池数据: " << sverify::ws_variable_pool_dump(false) << std::endl;
                } else if (op == 3) {
                    std::cout << "变量池数据(含密文): " << sverify::ws_variable_pool_dump(true) << std::endl;
                } else if (op == 4) {
                    sverify::verify_json hb = {};
                    int back_seconds = -1;
                    if (sverify::ws_variable_pool_decrypt_by_now(hb, back_seconds, true)) {
                        std::cout << "回溯解密成功, 回退秒数: " << back_seconds << std::endl;
                        std::cout << "变量: " << hb.variables << std::endl;
                        std::cout << "变量时间戳: " << hb.timestamp << std::endl;
                    } else {
                        std::cout << "回溯解密失败: " << hb.error_message << std::endl;
                    }
                } else if (op == 5) {
                    std::cout << "WS持久连接: " << (sverify::user_ws_connected() ? "存在" : "不存在/已掉线") << std::endl;
                } else if (op == 6) {
                    sverify::ws_user_disconnect(true);
                } else {
                    std::cout << "未知命令，请输入0/1/2/3/4/5/6" << std::endl;
                }
            }
        } break;
        case 12: {
            std::cout << "-- 测试网络验证-卡密WS心跳" << std::endl;
            std::cout << "请输入卡密心跳token:" << std::endl;
            std::string card_token;
            std::cin >> card_token;

            std::atomic<bool> card_ws_running{true};
            std::thread card_ws_reconnect_thread([&]() {
                while (card_ws_running.load()) {
                    sverify::verify_json j{};
                    if (!sverify::card_ws_connect(card_token, j, false)) {
                        std::cout << "[card-ws] 连接失败: " << j.error_message << std::endl;
                        if (!card_ws_running.load()) break;
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        continue;
                    }
                    std::cout << "[card-ws] 连接成功" << std::endl;
                    break;
                }
            });

            std::cout << "等待卡密WS连接(最多15秒)..." << std::endl;
            const auto card_ws_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
            while (std::chrono::steady_clock::now() < card_ws_deadline && !sverify::card_ws_connected()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            if (card_ws_reconnect_thread.joinable()) {
                card_ws_reconnect_thread.join();
            }

            if (!sverify::card_ws_connected()) {
                std::cout << "卡密WS连接失败" << std::endl;
                break;
            }

            std::cout << "卡密WS已连接，等待变量推送..." << std::endl;
            std::cout << "0=退出 1=获取变量 2=连接状态" << std::endl;

            while (true) {
                int op = custom_sutils::get_input_int("请输入命令(0/1/2):");
                if (op == 0) {
                    sverify::card_ws_disconnect(false);
                    std::cout << "卡密WS已断开" << std::endl;
                    break;
                } else if (op == 1) {
                    sverify::verify_json var_json = {};
                    if (sverify::card_ws_get_variables(var_json, false)) {
                        std::cout << "获取变量成功:" << std::endl;
                        std::cout << "  变量: " << var_json.variables << std::endl;
                        std::cout << "  时间戳: " << var_json.timestamp << std::endl;
                    } else {
                        std::cout << "获取变量失败: " << var_json.error_message << std::endl;
                    }
                } else if (op == 2) {
                    std::cout << "卡密WS连接: " << (sverify::card_ws_connected() ? "存在" : "不存在/已掉线") << std::endl;
                } else {
                    std::cout << "未知命令" << std::endl;
                }
            }
        } break;
        default:
            break;
    }


    std::cout << "欢迎下次使用! GoodNight! --阿夜" << std::endl;
    sverify::ws_user_disconnect(false);
    return 0;
}
