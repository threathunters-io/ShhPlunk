#define _GNU_SOURCE

#include <string>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <sys/ptrace.h>
#include <unistd.h>
#include <limits.h>
#include <iterator>
#include <fstream>

// follow a symlink
std::string do_readlink(std::string const& path) {
    char buff[PATH_MAX];
    ssize_t len = ::readlink(path.c_str(), buff, sizeof(buff)-1);
    if (len != -1) {
        buff[len] = '\0';
        return std::string(buff);
    }
    return "";
}

// get PIDs of all splunkd processes
std::vector<pid_t> get_pids() {
    std::vector<pid_t> result;
    char buf[512];
    FILE *cmd_pipe = popen("pgrep splunkd | tr '\n' ' '", "r");
    fgets(buf, 512, cmd_pipe);
    std::string line(buf);
    pclose( cmd_pipe );

    std::stringstream ss(line);
    std::string s_pid;
    while (ss >> s_pid) {
        result.push_back(strtoul(s_pid.c_str(), NULL, 10));
    }

    if(result.size() == 0 || result[0] == 0) {
        throw std::runtime_error("splunkd process not found\n");
    }
    return result;
}

// get base address of splunkd process
void* get_base(pid_t PID) {
    char buf[1024];
    std::string cmd = "head -1 /proc/" + std::to_string(PID) + "/maps | cut -d '-' -f1";
    FILE *cmd_pipe = popen(cmd.c_str(), "r");
    fgets(buf, 1024, cmd_pipe);
    std::string addr(buf);
    pclose( cmd_pipe );
    uint64_t res = -1;
    sscanf( addr.c_str() , "%llx" , &res);
    return (void*)res;
}


// signature scan
uint64_t scan(std::string path, std::vector<unsigned char> pattern) {
    std::cout << "reading binary..." << std::endl;
    std::ifstream file(path, std::ios::binary);

    file.unsetf(std::ios::skipws);
    std::streampos fileSize;

    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> bytes;
    bytes.reserve(fileSize);

    // read data into stream
    bytes.insert(bytes.begin(),
            std::istream_iterator<unsigned char>(file),
            std::istream_iterator<unsigned char>());

    std::cout << "searching for pattern..." << std::endl;
    for (uint64_t i = 0; i < bytes.size(); i++)
    {
        bool found = true;
        for (uint64_t j = 0; j < pattern.size(); j++)
        {
            if (pattern[j] != 0xAA && pattern[j] != bytes[i+j])
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return i;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    auto PIDs = get_pids();
    uint64_t offset = 0;

    // pattern for instruction to patch
    // 0F84?0000?80BBA000000000
    std::vector<unsigned char> pattern_vec = {0x0F, 0x84, 0xAA, 0x00, 0x00, 0xAA, 0x80, 0xBB, 0xA0, 0x00, 0x00, 0x00, 0x00};

    for(auto it=PIDs.begin(); it != PIDs.end(); it++) {
        pid_t PID = *it;
        std::cout << "Using PID: " << PID << std::endl;
        std::string splunk_path = do_readlink("/proc/" + std::to_string(PID) + "/exe");
        std::cout << "splunkd binary is at " << splunk_path << std::endl;

        if(offset == 0) {
            offset = scan(splunk_path, pattern_vec);
        }

        void *addr = get_base(PID) + offset;
        unsigned char resBuf[8];


        ptrace(PTRACE_ATTACH, PID, 0, 0);

        union u{
            long int val;
            char chars[8];
        } data;

        int bufferLength = sizeof(data.chars);

        data.val = ptrace(PTRACE_PEEKDATA, PID, addr, NULL);

        std::vector<unsigned char> res(data.chars, data.chars + bufferLength);

        std::cout << "reading @ " << addr << std::endl;
        for(auto it=res.begin(); it!=res.end(); it++) {
            std::cout << std::hex << (int)*it << std::dec;
        }
        std::cout << std::endl;

        std::cout << "patching @ " << addr << std::endl;
        std::vector<unsigned char> toWrite = res;
        toWrite[0] = 0x90; // nop
        toWrite[1] = 0xe9; // jmp
        int i = 0;
        for(auto it = toWrite.begin(); it!=toWrite.end(); it++) {
            ptrace(PTRACE_POKEDATA, PID, addr + i, *it);
            i++;
        }
        ptrace(PTRACE_CONT, PID, 0, 0);

        std::cout << "Done." <<  std::endl;
    }
}
