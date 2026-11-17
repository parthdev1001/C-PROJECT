#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include "console.h"
#include "types.h"
#include "capture.h"
#include "parser.h"
#include "filter.h"
#include "display.h"
#include "stats.h"
#include "detector.h"

static volatile sig_atomic_t g_capture_interrupted = 0;
static PacketStats g_c_stats;
static PacketFilter g_c_filter;
static FILE *g_c_log_fp = NULL;
static int g_c_verbose = 0;
static uint64_t g_c_max_packets = 0;
static uint64_t g_c_matched = 0;
static char g_c_log_path[256] = "";

static void console_sigint_handler(int signum) {
    (void)signum;
    g_capture_interrupted = 1;
    capture_stop();
}

static void console_packet_cb(u_char *user, const struct pcap_pkthdr *header, const u_char *buffer) {
    (void)user;
    if (g_capture_interrupted) return;

    ParsedPacket pkt;
    if (parse_packet(header, buffer, &pkt) != 0) return;

    if (!filter_match(&g_c_filter, &pkt)) return;

    g_c_matched++;
    stats_update(&g_c_stats, &pkt);
    display_packet(&pkt, g_c_log_fp, g_c_verbose);
    detector_inspect(&pkt, g_c_log_fp);

    if (g_c_matched % 20 == 0) {
        stats_print_running(&g_c_stats);
    }

    if (g_c_max_packets > 0 && g_c_matched >= g_c_max_packets) {
        printf("\n[*] Reached packet limit (%lu packets).\n", (unsigned long)g_c_max_packets);
        capture_stop();
    }
}

static void print_menu(void) {
    printf("\n");
    printf("┌────────────────────────────────────────────────────────┐\n");
    printf("│             NetSnoop Interactive Menu                  │\n");
    printf("├────────────────────────────────────────────────────────┤\n");
    printf("│  [1] List Available Interfaces                         │\n");
    printf("│  [2] Start Live Packet Capture                         │\n");
    printf("│  [3] Analyze Offline PCAP File                         │\n");
    printf("│  [4] Configure Packet Filters                          │\n");
    printf("│  [5] View Current Statistics                           │\n");
    printf("│  [6] Toggle Verbose Payload Dump (Current: %-3s)        │\n", g_c_verbose ? "ON" : "OFF");
    printf("│  [7] Set Log File (Current: %-26s)│\n", g_c_log_path[0] ? g_c_log_path : "None");
    printf("│  [8] Clear Screen                                      │\n");
    printf("│  [9] Exit Console                                      │\n");
    printf("└────────────────────────────────────────────────────────┘\n\n");
}

static void print_cli_help(void) {
    printf("\nAvailable Console Commands:\n");
    printf("  menu                  - Display numbered interactive menu\n");
    printf("  list                  - List network interfaces\n");
    printf("  capture [dev] [count] - Live capture (e.g. 'capture eth0 50')\n");
    printf("  replay [file] [count] - Replay PCAP (default: samples/sample_traffic.pcap)\n");
    printf("  filter [proto] [port] - Set filter (e.g. 'filter TCP 80', 'filter ALL')\n");
    printf("  show                  - Display current settings and active filters\n");
    printf("  stats                 - Print cumulative statistics\n");
    printf("  verbose <on|off>      - Toggle payload hex-dump\n");
    printf("  log <file|off>        - Enable/disable logging to file\n");
    printf("  clear                 - Clear terminal screen\n");
    printf("  help                  - Show this command reference\n");
    printf("  exit / quit           - Return to shell\n\n");
}

static void show_current_settings(void) {
    printf("\n--- Current NetSnoop Configuration ---\n");
    printf("  Active Protocol Filter : %s\n", g_c_filter.protocol);
    printf("  Active Port Filter     : %u\n", g_c_filter.port);
    printf("  Source IP Filter       : %s\n", g_c_filter.src_ip[0] ? g_c_filter.src_ip : "(any)");
    printf("  Dest IP Filter         : %s\n", g_c_filter.dest_ip[0] ? g_c_filter.dest_ip : "(any)");
    printf("  Verbose Payload Dump   : %s\n", g_c_verbose ? "ENABLED" : "DISABLED");
    printf("  Log File               : %s\n", g_c_log_path[0] ? g_c_log_path : "(none)");
    printf("  Total Packets Logged   : %lu\n", (unsigned long)g_c_stats.total_packets);
    printf("--------------------------------------\n\n");
}

static void execute_live_capture(const char *dev, uint64_t count) {
    g_c_max_packets = count;
    g_c_matched = 0;
    g_capture_interrupted = 0;

    printf("\n[*] Starting live capture on %s (limit: %lu, Ctrl+C to stop)...\n\n",
           dev && dev[0] ? dev : "(default)", (unsigned long)count);

    if (capture_init(dev && dev[0] ? dev : NULL, SNAP_LEN, PROMISC_MODE, TIMEOUT_MS) != 0) {
        return;
    }

    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = console_sigint_handler;
    sigaction(SIGINT, &sa, &old_sa);

    capture_start(console_packet_cb, NULL);

    sigaction(SIGINT, &old_sa, NULL);
    capture_cleanup();

    printf("\n[*] Live capture stopped. Summary:\n");
    stats_print(&g_c_stats, g_c_log_fp);
}

static void execute_replay_pcap(const char *path, uint64_t count) {
    const char *target_file = (path && path[0]) ? path : "samples/sample_traffic.pcap";
    g_c_max_packets = count;
    g_c_matched = 0;
    g_capture_interrupted = 0;

    printf("\n[*] Replaying PCAP file: %s (limit: %lu)...\n\n",
           target_file, (unsigned long)count);

    if (capture_open_file(target_file) != 0) {
        return;
    }

    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = console_sigint_handler;
    sigaction(SIGINT, &sa, &old_sa);

    capture_start(console_packet_cb, NULL);

    sigaction(SIGINT, &old_sa, NULL);
    capture_cleanup();

    printf("\n[*] PCAP Replay completed. Summary:\n");
    stats_print(&g_c_stats, g_c_log_fp);
}

void console_run(void) {
    char line[256];
    char cmd[64], arg1[128], arg2[64];

    filter_init(&g_c_filter);
    stats_init(&g_c_stats);
    detector_init();

    display_banner();
    printf("NetSnoop Management Console v1.0\n");
    printf("Type 'help' for command list, 'menu' for options menu, or select [1-9].\n\n");

    while (1) {
        printf("\033[1;36mnetsnoop>\033[0m ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break; /* EOF */
        }

        /* Strip trailing newline */
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        cmd[0] = '\0';
        arg1[0] = '\0';
        arg2[0] = '\0';
        sscanf(line, "%63s %127s %63s", cmd, arg1, arg2);

        /* Handle numeric menu selections */
        if (strcmp(cmd, "1") == 0) {
            capture_list_devices();
        } else if (strcmp(cmd, "2") == 0) {
            char iface[64] = {0};
            char cnt_str[32] = {0};
            printf("Enter interface name (leave blank for auto): ");
            fflush(stdout);
            if (fgets(iface, sizeof(iface), stdin)) {
                iface[strcspn(iface, "\r\n")] = '\0';
            }
            printf("Enter packet limit (0 for unlimited): ");
            fflush(stdout);
            uint64_t limit = 0;
            if (fgets(cnt_str, sizeof(cnt_str), stdin)) {
                limit = (uint64_t)strtoull(cnt_str, NULL, 10);
            }
            execute_live_capture(iface, limit);
        } else if (strcmp(cmd, "3") == 0) {
            char fpath[128] = {0};
            printf("Enter PCAP file path (default: samples/sample_traffic.pcap): ");
            fflush(stdout);
            if (fgets(fpath, sizeof(fpath), stdin)) {
                fpath[strcspn(fpath, "\r\n")] = '\0';
            }
            execute_replay_pcap(fpath[0] ? fpath : NULL, 0);
        } else if (strcmp(cmd, "4") == 0) {
            char pstr[32] = {0};
            char portstr[32] = {0};
            printf("Enter protocol to filter (ALL, TCP, UDP, ICMP, HTTP, DNS): ");
            fflush(stdout);
            if (fgets(pstr, sizeof(pstr), stdin)) {
                pstr[strcspn(pstr, "\r\n")] = '\0';
                if (filter_set_protocol(&g_c_filter, pstr) != 0) {
                    printf("[!] Invalid protocol. Kept previous: %s\n", g_c_filter.protocol);
                }
            }
            printf("Enter port to filter (0 for any): ");
            fflush(stdout);
            if (fgets(portstr, sizeof(portstr), stdin)) {
                uint16_t port = (uint16_t)atoi(portstr);
                filter_set_port(&g_c_filter, port);
            }
            show_current_settings();
        } else if (strcmp(cmd, "5") == 0) {
            stats_print(&g_c_stats, g_c_log_fp);
        } else if (strcmp(cmd, "6") == 0) {
            g_c_verbose = !g_c_verbose;
            printf("[*] Verbose payload dump is now: %s\n", g_c_verbose ? "ENABLED" : "DISABLED");
        } else if (strcmp(cmd, "7") == 0) {
            char lpath[128] = {0};
            printf("Enter log file path (or 'off' to disable): ");
            fflush(stdout);
            if (fgets(lpath, sizeof(lpath), stdin)) {
                lpath[strcspn(lpath, "\r\n")] = '\0';
                if (g_c_log_fp) {
                    fclose(g_c_log_fp);
                    g_c_log_fp = NULL;
                }
                if (strcasecmp(lpath, "off") == 0 || lpath[0] == '\0') {
                    g_c_log_path[0] = '\0';
                    printf("[*] Logging disabled.\n");
                } else {
                    snprintf(g_c_log_path, sizeof(g_c_log_path), "%s", lpath);
                    g_c_log_fp = fopen(g_c_log_path, "a");
                    if (g_c_log_fp) {
                        printf("[*] Logging active to: %s\n", g_c_log_path);
                    } else {
                        perror("[!] Could not open log file");
                        g_c_log_path[0] = '\0';
                    }
                }
            }
        } else if (strcmp(cmd, "8") == 0) {
            printf("\033[2J\033[H");
        } else if (strcmp(cmd, "9") == 0 || strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            printf("[*] Exiting NetSnoop Console. Goodbye!\n");
            break;
        }
        /* Handle text command names */
        else if (strcmp(cmd, "menu") == 0) {
            print_menu();
        } else if (strcmp(cmd, "help") == 0) {
            print_cli_help();
        } else if (strcmp(cmd, "list") == 0 || strcmp(cmd, "interfaces") == 0) {
            capture_list_devices();
        } else if (strcmp(cmd, "show") == 0) {
            show_current_settings();
        } else if (strcmp(cmd, "stats") == 0) {
            stats_print(&g_c_stats, g_c_log_fp);
        } else if (strcmp(cmd, "clear") == 0) {
            printf("\033[2J\033[H");
        } else if (strcmp(cmd, "verbose") == 0) {
            if (strcasecmp(arg1, "on") == 0) g_c_verbose = 1;
            else if (strcasecmp(arg1, "off") == 0) g_c_verbose = 0;
            else g_c_verbose = !g_c_verbose;
            printf("[*] Verbose payload dump: %s\n", g_c_verbose ? "ENABLED" : "DISABLED");
        } else if (strcmp(cmd, "log") == 0) {
            if (g_c_log_fp) { fclose(g_c_log_fp); g_c_log_fp = NULL; }
            if (arg1[0] == '\0' || strcasecmp(arg1, "off") == 0) {
                g_c_log_path[0] = '\0';
                printf("[*] Logging disabled.\n");
            } else {
                snprintf(g_c_log_path, sizeof(g_c_log_path), "%s", arg1);
                g_c_log_fp = fopen(g_c_log_path, "a");
                if (g_c_log_fp) {
                    printf("[*] Logging to %s\n", g_c_log_path);
                } else {
                    perror("[!] Could not open log file");
                    g_c_log_path[0] = '\0';
                }
            }
        } else if (strcmp(cmd, "filter") == 0) {
            if (arg1[0] == '\0') {
                show_current_settings();
            } else if (strcasecmp(arg1, "reset") == 0) {
                filter_init(&g_c_filter);
                printf("[*] Filters reset to default (ALL).\n");
            } else {
                if (filter_set_protocol(&g_c_filter, arg1) == 0) {
                    printf("[*] Protocol filter set to: %s\n", g_c_filter.protocol);
                } else {
                    printf("[!] Unknown protocol '%s'. Supported: ALL, TCP, UDP, ICMP, HTTP, DNS\n", arg1);
                }
                if (arg2[0] != '\0') {
                    filter_set_port(&g_c_filter, (uint16_t)atoi(arg2));
                    printf("[*] Port filter set to: %u\n", g_c_filter.port);
                }
            }
        } else if (strcmp(cmd, "capture") == 0) {
            uint64_t count = 0;
            if (arg2[0] != '\0') {
                count = (uint64_t)strtoull(arg2, NULL, 10);
            }
            execute_live_capture(arg1[0] ? arg1 : NULL, count);
        } else if (strcmp(cmd, "replay") == 0) {
            uint64_t count = 0;
            if (arg2[0] != '\0') {
                count = (uint64_t)strtoull(arg2, NULL, 10);
            }
            execute_replay_pcap(arg1[0] ? arg1 : NULL, count);
        } else {
            printf("[!] Unknown command: '%s'. Type 'help' or 'menu'.\n", cmd);
        }
    }

    if (g_c_log_fp) {
        fclose(g_c_log_fp);
        g_c_log_fp = NULL;
    }
    detector_cleanup();
}
