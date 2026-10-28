#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <sys/stat.h>

#define LOG_FILE "/storage/emulated/0/@/log/微信内存监控_C版.csv"
#define BATCH_SIZE 25
#define MAX_BUFFER_SIZE 131072 // 128KB 落盘缓存池
// 满血版：直接给 32MB 独立内存池，不要心疼内存，确保绝对不截断！
#define SMAPS_BUF_SIZE (32 * 1024 * 1024) 

long long get_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// 全局共享 32MB 极速缓冲区
char *smaps_buf = NULL;

void parse_smaps_fast(const char *pid, double *size, double *rss, double *pss, 
                      double *sclean, double *sdirty, double *pclean, double *pdirty, double *swap) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%s/smaps", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return;

    // 一次性读入 32MB 内存
    size_t bytes_read = fread(smaps_buf, 1, SMAPS_BUF_SIZE - 1, f);
    smaps_buf[bytes_read] = '\0';
    fclose(f);

    // 防范“半行截断”：如果刚好塞满了 32MB，把最后半行砍掉，防止解析出乱码数值
    if (bytes_read == SMAPS_BUF_SIZE - 1) {
        char *last_newline = strrchr(smaps_buf, '\n');
        if (last_newline) *last_newline = '\0';
    }

    char *line = smaps_buf;
    char *next_line;
    
    // 暴力指针跳转解析
    while (line && *line) {
        next_line = strchr(line, '\n');
        if (next_line) *next_line = '\0'; 

        // 优化：用 line[0] 直接判断首字母，减少不必要的 strncmp 完整匹配
        if (line[0] == 'S') {
            if (strncmp(line, "Size:", 5) == 0) *size += atoll(line + 5) / 1024.0;
            else if (strncmp(line, "Shared_Clean:", 13) == 0) *sclean += atoll(line + 13) / 1024.0;
            else if (strncmp(line, "Shared_Dirty:", 13) == 0) *sdirty += atoll(line + 13) / 1024.0;
            else if (strncmp(line, "Swap:", 5) == 0) *swap += atoll(line + 5) / 1024.0;
        } else if (line[0] == 'R') {
            if (strncmp(line, "Rss:", 4) == 0) *rss += atoll(line + 4) / 1024.0;
        } else if (line[0] == 'P') {
            if (strncmp(line, "Pss:", 4) == 0) *pss += atoll(line + 4) / 1024.0;
            else if (strncmp(line, "Private_Clean:", 14) == 0) *pclean += atoll(line + 14) / 1024.0;
            else if (strncmp(line, "Private_Dirty:", 14) == 0) *pdirty += atoll(line + 14) / 1024.0;
        }

        if (next_line) line = next_line + 1;
        else break;
    }
}

int main() {
    mkdir("/storage/emulated/0/@/log", 0777);
    
    FILE *log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        printf("无法打开日志文件，请检查权限\n");
        return 1;
    }
    
    fseek(log_fp, 0, SEEK_END);
    if (ftell(log_fp) == 0) {
        fprintf(log_fp, "时间, 微信总USS, 系统可用, 进程数, 主进程, push进程, appbrand0, appbrand1, 其他进程, 总Size, 总Rss, 总Pss, 总SharedClean, 总SharedDirty, 总PrivateClean, 总PrivateDirty, 总Swap\n");
        fflush(log_fp);
    }

    // 初始化全局大池子
    smaps_buf = (char *)malloc(SMAPS_BUF_SIZE);
    char *buffer = (char *)malloc(MAX_BUFFER_SIZE);
    if (!smaps_buf || !buffer) {
        printf("内存分配失败！\n");
        return 1;
    }
    buffer[0] = '\0';
    int batch_count = 0;

    printf("监控启动... (Android 9 32MB满血版, 单次采集耗时如下)\n");

    while (1) {
        long long start_ms = get_ms();
        double sys_avail_mb = 0;
        
        FILE *meminfo = fopen("/proc/meminfo", "r");
        if (meminfo) {
            char mline[256];
            while (fgets(mline, sizeof(mline), meminfo)) {
                if (strncmp(mline, "MemAvailable:", 13) == 0) {
                    sys_avail_mb = atoll(mline + 13) / 1024.0;
                    break;
                }
            }
            fclose(meminfo);
        }

        DIR *dir = opendir("/proc");
        if (!dir) { usleep(200000); continue; }

        int proc_count = 0;
        double total_uss = 0;
        double val_main = 0, val_push = 0, val_b0 = 0, val_b1 = 0;
        char val_other[1024] = {0}; 

        double t_size = 0, t_rss = 0, t_pss = 0, t_sclean = 0, t_sdirty = 0, t_pclean = 0, t_pdirty = 0, t_swap = 0;

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;

            // 读 cmdline 拿完整进程名
            char cmdline_path[64];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
            FILE *cmdf = fopen(cmdline_path, "r");
            if (!cmdf) continue;
            
            char full_name[256] = {0};
            size_t read_bytes = fread(full_name, 1, sizeof(full_name) - 1, cmdf);
            fclose(cmdf);

            if (read_bytes > 0) {
                for (size_t i = 0; i < read_bytes; i++) {
                    if (full_name[i] == '\0') full_name[i] = ' ';
                }
            }

            // 匹配微信进程
            if (strncmp(full_name, "com.tencent.mm", 14) == 0) {
                proc_count++;
                
                double p_size = 0, p_rss = 0, p_pss = 0, p_sclean = 0, p_sdirty = 0, p_pclean = 0, p_pdirty = 0, p_swap = 0;
                parse_smaps_fast(entry->d_name, &p_size, &p_rss, &p_pss, &p_sclean, &p_sdirty, &p_pclean, &p_pdirty, &p_swap);

                t_size += p_size; t_rss += p_rss; t_pss += p_pss;
                t_sclean += p_sclean; t_sdirty += p_sdirty;
                t_pclean += p_pclean; t_pdirty += p_pdirty; t_swap += p_swap;

                double p_uss = p_pclean + p_pdirty;
                total_uss += p_uss;

                // 精确分类
                if (strcmp(full_name, "com.tencent.mm") == 0 || strncmp(full_name, "com.tencent.mm ", 15) == 0) {
                    val_main = p_uss;
                } else if (strstr(full_name, "push") || strstr(full_name, "Push")) {
                    val_push = p_uss;
                } else if (strstr(full_name, "appbrand0")) {
                    val_b0 = p_uss;
                } else if (strstr(full_name, "appbrand1")) {
                    val_b1 = p_uss;
                } else {
                    char *short_name = strchr(full_name, ':');
                    if (short_name) short_name++; else short_name = full_name;
                    char *space = strchr(short_name, ' ');
                    if (space) *space = '\0'; // 截掉多余参数
                    
                    char temp[128];
                    snprintf(temp, sizeof(temp), "%s:%.1fM", short_name, p_uss);
                    if (strlen(val_other) == 0) strcpy(val_other, temp);
                    else if (strlen(val_other) + strlen(temp) + 4 < sizeof(val_other)) {
                        strcat(val_other, " | "); strcat(val_other, temp);
                    }
                }
            }
        }
        closedir(dir);

        long long cost = get_ms() - start_ms;
        time_t t = time(NULL);
        struct tm *tm_info = localtime(&t);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

        if (strlen(val_other) == 0) strcpy(val_other, "0");

        char line[2048];
        snprintf(line, sizeof(line), 
            "%s.%03lld, %.1f, %.1f, %d, %.1f, %.1f, %.1f, %.1f, %s, %.1f, %.1f, %.1f, %.1f, %.1f, %.1f, %.1f, %.1f\n",
            time_str, start_ms % 1000, total_uss, sys_avail_mb, proc_count, 
            val_main, val_push, val_b0, val_b1, val_other,
            t_size, t_rss, t_pss, t_sclean, t_sdirty, t_pclean, t_pdirty, t_swap);

        if (strlen(buffer) + strlen(line) < MAX_BUFFER_SIZE - 100) {
            strcat(buffer, line);
            batch_count++;
        }

        // 终端显示实时耗时
        printf("\r[%s] USS:%.1f | 进程:%d | 耗时:%lldms   ", time_str, total_uss, proc_count, cost);
        fflush(stdout);

        if (batch_count >= BATCH_SIZE) {
            fprintf(log_fp, "%s", buffer);
            fflush(log_fp);
            batch_count = 0;
            buffer[0] = '\0'; 
            printf("\n>>> [落盘] 已写入 %d 条 (当前单次采集耗时: %lldms)\n", BATCH_SIZE, cost);
        }

        // 动态睡眠保护机制：如果采集非常快（比如只用了 20ms），就睡 180ms，保证总间隔约为 200ms
        long long sleep_time = 200000 - (cost * 1000);
        if (sleep_time < 0) sleep_time = 0; // 防负数
        usleep(sleep_time); 
    }
    
    free(smaps_buf);
    free(buffer);
    fclose(log_fp);
    return 0;
}