#ifndef SEA2_VERIFY_H
#define SEA2_VERIFY_H

#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>

#include <any>
extern std::string ciphergate_host;   // CipherGate host, only this URL part is configurable
extern std::string ciphergate_app_id; // 网页登录场景仍可能使用
extern std::string ciphergate_client_version;// 客户端版本号(用于更新检查)
extern std::string ciphergate_app_key;   // CipherGate app key
extern std::string ciphergate_app_secret;// CipherGate app secret
extern std::string ciphergate_aes_key;   // CipherGate AES key(16字节)


extern std::unordered_map<std::string, std::function<std::any(std::vector<std::any>)>> method_map;

namespace sverify {

    struct verify_json {
        bool success;// 是否成功
        bool expire; // 是否过期

        bool have_update;// 是否有更新
        long status_code;// 本次网络请求的状态码 常见200成功 401认证失败 302重定向
        long available;  // 剩余可用时间秒

        int card_id;          //卡密ID
        int unbind_number;    //解绑次数
        int bind_number;      //绑定次数
        std::string end_time; // 到期时间
        std::string card_type;// 卡类型
        std::string notice;   // 获取的公告
        std::string variables;// 获取的变量
        std::string core;     //核心数据
        std::string token;    // 心跳token

        std::string username;// 获取的账号
        std::string password;// 获取的密码

        std::string update_url;    // 更新链接
        std::string update_message;// 更新信息
        bool update_must;          // 是否强制更新
        time_t timestamp;          // 服务器时间戳
        std::string error_message; // 失败的错误信息
        FILE *file;                // 文件句柄
        size_t file_size;          // 文件大小
        bool potentially_shared;   // 心跳间隔>60秒，疑似多用户共用
    };


    bool get_notice(verify_json &json, bool log = false);                                                                                                               // 获取程序公告
    bool get_update(verify_json &json, bool log = false);                                                                                                               // 获取程序更新信息
    bool get_variables(verify_json &json, bool log = false);                                                                                                            // 获取程序变量
    bool bind_card(const std::string &kami_, const std::string &imei_, sverify::verify_json &json_, bool log = false);                                                  // 单码卡密绑定
    bool unbind_card(const std::string &kami_, const std::string &imei_, sverify::verify_json &json_, bool log = false);                                                // 单码卡密换绑
    bool card_heartbeat(const std::string &token_, sverify::verify_json &json_, bool log = false);                                                                     // 单码卡密心跳
    bool user_login(const std::string &username_, const std::string &password_, sverify::verify_json &json_, bool log = false);                                         // 用户登录
    bool user_heart_beat(const std::string &cid, const std::string &token_, sverify::verify_json &json_, bool log = false);                                             // 用户心跳
    void ws_user_disconnect(bool log = false);                                                                                                                            // 主动断开WS用户连接
    bool user_ws_connected();                                                                                                                                             // 用户WS是否仍为持久连接(监听线程在跑、未掉线)
    // 断线重连：已连接则直接成功；否则等价于再次 user_login（会先停旧监听再全量握手）。可在业务线程里定时调用，失败时 sleep 退避再试。
    bool user_ws_ensure_connected(const std::string &username_, const std::string &password_, sverify::verify_json &json_, bool log = false);
    size_t ws_variable_pool_size();                                                                                                                                       // 变量池数量
    std::string ws_variable_pool_dump(bool include_cipher = false);                                                                                                       // 变量池全部数据(JSON)
    bool ws_variable_pool_decrypt_by_now(sverify::verify_json &json_, int &back_seconds, bool log = false);                                                            // 从当前时间向前回溯解密
    std::any call_function(const std::function<std::any(std::vector<std::any>)>& func, std::vector<std::any> args);                                                                                                                                                 // 初始化逻辑方法
    void safe_module(bool log);                                                                                                                                         //启用安全模式
}


#endif//SEA2_VERIFY_H
