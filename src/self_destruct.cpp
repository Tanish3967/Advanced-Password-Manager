#include "../include/self_destruct.h"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <string>

// Self-Destruct Mode implementation

void SelfDestruct::trigger_self_destruct(const std::string& data_file) {
    // Overwrite the file with zeros, then delete it
    std::fstream file(data_file, std::ios::in | std::ios::out | std::ios::binary);
    if (file.is_open()) {
        file.seekg(0, std::ios::end);
        std::streampos length = file.tellg();
        file.seekp(0, std::ios::beg);
        for (std::streampos i = 0; i < length; ++i) {
            file.put(0);
        }
        file.close();
    }
    std::remove(data_file.c_str());
}

void SelfDestruct::log_event(const std::string& event) {
    std::ofstream log("self_destruct.log", std::ios::app);
    if (log.is_open()) {
        log << event << std::endl;
        log.close();
    }
}

bool SelfDestruct::should_trigger(int failed_attempts, int max_attempts) {
    return failed_attempts >= max_attempts;
}
