 //
 // Created by root on 7/19/25.
 //

 #ifndef SEAV3_EASY_VERFY_H
 #define SEAV3_EASY_VERFY_H
 #include <functional>
 #include <iostream>
 #include <obfuscate.h>
 #include <unordered_map>
 #include <any>
std::string ciphergate_host = OBFUSCATE("https://www.ayssu.com");// 仅 host 可配置
std::string ciphergate_app_id = OBFUSCATE("1");
std::string ciphergate_client_version = OBFUSCATE("1.0.0");
std::string ciphergate_app_key = OBFUSCATE("iLyilmnIJJXRpa0jPbYrNs01eeMoTH8q");
std::string ciphergate_app_secret = OBFUSCATE("HHjXxmUNtSeERqUGLxu2mmGTCMzdSmMNXAAHTB8ZRFzHiKgQIpSegy4iwrRFuE1p");
std::string ciphergate_aes_key = OBFUSCATE("cg_demo_key_7756");

 std::unordered_map<std::string, std::function<std::any(std::vector<std::any>)>> method_map;
 #endif //SEAV3_EASY_VERFY_H

