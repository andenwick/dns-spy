/*
 * DNS Spy - Red Team Edition
 * Network security tool for DNS analysis and threat detection
 *
 * Features:
 * - Real-time DNS query capture
 * - DNS exfiltration detection (entropy analysis)
 * - DGA (Domain Generation Algorithm) detection
 * - DNS tunneling detection
 * - DoH (DNS-over-HTTPS) connection detection
 * - Suspicious TLD alerting
 * - Full session logging
 * - Statistics and top talkers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")

/* ==================== CONFIGURATION ==================== */

#define MAX_DOMAINS 10000
#define MAX_DOMAIN_LEN 256
#define ENTROPY_THRESHOLD 3.5      /* Flag domains with entropy above this */
#define SUBDOMAIN_LEN_THRESHOLD 30 /* Flag subdomains longer than this */
#define LABEL_COUNT_THRESHOLD 8    /* Flag domains with more labels than this */

/* Known DoH server IPs */
const char* DOH_SERVERS[] = {
    "8.8.8.8", "8.8.4.4",           /* Google */
    "1.1.1.1", "1.0.0.1",           /* Cloudflare */
    "9.9.9.9", "149.112.112.112",   /* Quad9 */
    "208.67.222.222", "208.67.220.220", /* OpenDNS */
    "185.228.168.9", "185.228.169.9",   /* CleanBrowsing */
    NULL
};

/* Suspicious TLDs often used in attacks */
const char* SUSPECT_TLDS[] = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".cc", ".su", ".buzz", ".work", ".click",
    ".link", ".info", ".online", ".site", ".club",
    NULL
};

/* Whitelisted domains - known-good CDN/cloud providers */
const char* WHITELIST_DOMAINS[] = {
    "microsoft.com", "google.com", "apple.com", "windows.com",
    "amazonaws.com", "cloudflare.com", "akamai.net", "azure.com",
    "office.com", "live.com", "msn.com", "bing.com",
    "windowsupdate.com", "gstatic.com", "googleapis.com",
    "googleusercontent.com", "azureedge.net", "trafficmanager.net",
    NULL
};

/* ==================== CONSOLE COLORS ==================== */

/* Ensure this is defined (missing in older SDKs) */
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/* Global flag - set to 0 if console doesn't support ANSI */
int g_use_colors = 1;

/* Color codes - will be empty strings if colors disabled */
const char* COLOR_RESET   = "\033[0m";
const char* COLOR_RED     = "\033[91m";
const char* COLOR_YELLOW  = "\033[93m";
const char* COLOR_GREEN   = "\033[92m";
const char* COLOR_CYAN    = "\033[96m";
const char* COLOR_MAGENTA = "\033[95m";
const char* COLOR_DIM     = "\033[90m";

/* ==================== DATA STRUCTURES ==================== */

typedef struct {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ethertype;
} ethernet_header;

typedef struct {
    unsigned char  version_ihl;
    unsigned char  tos;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    unsigned int   src_addr;
    unsigned int   dest_addr;
} ip_header;

typedef struct {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
} udp_header;

typedef struct {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned int   seq_num;
    unsigned int   ack_num;
    unsigned char  data_offset;
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent;
} tcp_header;

typedef struct {
    unsigned short id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answers;
    unsigned short authority;
    unsigned short additional;
} dns_header;

/* Statistics tracking */
typedef struct {
    char domain[MAX_DOMAIN_LEN];
    int count;
    int flags;  /* Bitmap of alerts triggered */
} domain_stats;

/* Alert flags */
#define ALERT_DGA        0x01
#define ALERT_EXFIL      0x02
#define ALERT_TUNNEL     0x04
#define ALERT_SUSPECT    0x08
#define ALERT_LONG_SUB   0x10

/* Global stats */
domain_stats g_stats[MAX_DOMAINS];
int g_stats_count = 0;
int g_total_queries = 0;
int g_total_alerts = 0;
FILE* g_logfile = NULL;

/* ==================== UTILITY FUNCTIONS ==================== */

/* Disable colors - use empty strings */
void disable_colors() {
    g_use_colors = 0;
    COLOR_RESET = "";
    COLOR_RED = "";
    COLOR_YELLOW = "";
    COLOR_GREEN = "";
    COLOR_CYAN = "";
    COLOR_MAGENTA = "";
    COLOR_DIM = "";
}

/* Enable ANSI colors and UTF-8 on Windows */
void enable_colors() {
    /* Set console to UTF-8 for box-drawing characters */
    SetConsoleOutputCP(65001);

    /* Enable ANSI escape sequences for colors */
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        disable_colors();
        return;
    }

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) {
        disable_colors();
        return;
    }

    if (!SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        disable_colors();
        return;
    }
}

/* Calculate Shannon entropy of a string */
double calculate_entropy(const char* str) {
    int freq[256] = {0};
    int len = strlen(str);
    if (len == 0) return 0;

    for (int i = 0; i < len; i++) {
        freq[(unsigned char)str[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/* Count consonants in a row (DGA indicator) */
int max_consonant_run(const char* str) {
    int max_run = 0, current_run = 0;
    const char* vowels = "aeiouAEIOU";

    for (int i = 0; str[i]; i++) {
        if (isalpha(str[i]) && !strchr(vowels, str[i])) {
            current_run++;
            if (current_run > max_run) max_run = current_run;
        } else {
            current_run = 0;
        }
    }
    return max_run;
}

/* Check if domain is whitelisted (known-good) */
int is_whitelisted(const char* domain) {
    for (int i = 0; WHITELIST_DOMAINS[i]; i++) {
        int dlen = strlen(domain);
        int wlen = strlen(WHITELIST_DOMAINS[i]);
        if (dlen >= wlen) {
            const char* suffix = domain + dlen - wlen;
            /* Match exact suffix (ends with whitelist domain) */
            if (strcmp(suffix, WHITELIST_DOMAINS[i]) == 0) {
                /* Ensure it's a proper subdomain (preceded by . or start of string) */
                if (suffix == domain || *(suffix - 1) == '.') {
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* Check if domain looks like DGA (randomly generated) */
int is_dga_domain(const char* domain) {
    /* Skip known CDNs and legitimate high-entropy domains */
    if (strstr(domain, "amazonaws.com")) return 0;
    if (strstr(domain, "cloudfront.net")) return 0;
    if (strstr(domain, "akamai")) return 0;
    if (strstr(domain, "cdn")) return 0;

    /* Get the first label (subdomain or domain name) */
    char first_label[128] = {0};
    const char* dot = strchr(domain, '.');
    if (dot) {
        int len = dot - domain;
        if (len > 127) len = 127;
        strncpy(first_label, domain, len);
    } else {
        strncpy(first_label, domain, 127);
    }

    if (strlen(first_label) < 6) return 0;

    double entropy = calculate_entropy(first_label);
    int consonant_run = max_consonant_run(first_label);
    int digit_count = 0;
    for (int i = 0; first_label[i]; i++) {
        if (isdigit(first_label[i])) digit_count++;
    }

    /* DGA indicators: high entropy + long consonant runs + digits mixed in */
    if (entropy > 3.8 && consonant_run >= 4) return 1;
    if (entropy > 4.0 && digit_count > 2) return 1;
    if (strlen(first_label) > 20 && entropy > 3.5) return 1;

    return 0;
}

/* Check for DNS exfiltration patterns */
int is_exfil_domain(const char* domain) {
    /* Skip whitelisted domains */
    if (is_whitelisted(domain)) return 0;

    /* Long encoded subdomains are suspicious */
    const char* dot = strchr(domain, '.');
    if (dot) {
        int first_label_len = dot - domain;
        if (first_label_len > SUBDOMAIN_LEN_THRESHOLD) {
            /* Check if it looks encoded (base64, hex) */
            double entropy = calculate_entropy(domain);
            if (entropy > 3.2) return 1;
        }
    }

    /* Count labels (dots + 1) */
    int labels = 1;
    for (int i = 0; domain[i]; i++) {
        if (domain[i] == '.') labels++;
    }
    if (labels > LABEL_COUNT_THRESHOLD) return 1;

    /* Very long total domain */
    if (strlen(domain) > 100) return 1;

    return 0;
}

/* Check for DNS tunneling patterns */
int is_tunnel_domain(const char* domain) {
    /* Known DNS tunneling tool signatures */
    if (strstr(domain, "dnscat")) return 1;
    if (strstr(domain, "iodine")) return 1;
    if (strstr(domain, "dns2tcp")) return 1;
    if (strstr(domain, "heyoka")) return 1;

    /* Multiple long subdomains with high entropy */
    int long_labels = 0;
    char copy[MAX_DOMAIN_LEN];
    strncpy(copy, domain, MAX_DOMAIN_LEN - 1);
    copy[MAX_DOMAIN_LEN - 1] = '\0';

    char* token = strtok(copy, ".");
    while (token) {
        if (strlen(token) > 20 && calculate_entropy(token) > 3.0) {
            long_labels++;
        }
        token = strtok(NULL, ".");
    }

    return long_labels >= 2;
}

/* Check for suspicious TLD */
int has_suspect_tld(const char* domain) {
    for (int i = 0; SUSPECT_TLDS[i]; i++) {
        int dlen = strlen(domain);
        int tlen = strlen(SUSPECT_TLDS[i]);
        if (dlen >= tlen && strcmp(domain + dlen - tlen, SUSPECT_TLDS[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Convert IP to string */
void ip_to_str(unsigned int ip, char* buf) {
    unsigned char* bytes = (unsigned char*)&ip;
    sprintf(buf, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/* Check if IP is a known DoH server */
int is_doh_server(const char* ip) {
    for (int i = 0; DOH_SERVERS[i]; i++) {
        if (strcmp(ip, DOH_SERVERS[i]) == 0) return 1;
    }
    return 0;
}

/* Get DoH provider name */
const char* get_doh_provider(const char* ip) {
    if (strcmp(ip, "8.8.8.8") == 0 || strcmp(ip, "8.8.4.4") == 0) return "Google";
    if (strcmp(ip, "1.1.1.1") == 0 || strcmp(ip, "1.0.0.1") == 0) return "Cloudflare";
    if (strcmp(ip, "9.9.9.9") == 0 || strcmp(ip, "149.112.112.112") == 0) return "Quad9";
    if (strcmp(ip, "208.67.222.222") == 0 || strcmp(ip, "208.67.220.220") == 0) return "OpenDNS";
    return "Unknown";
}

/* Update statistics for a domain */
void update_stats(const char* domain, int flags) {
    for (int i = 0; i < g_stats_count; i++) {
        if (strcmp(g_stats[i].domain, domain) == 0) {
            g_stats[i].count++;
            g_stats[i].flags |= flags;
            return;
        }
    }

    if (g_stats_count < MAX_DOMAINS) {
        strncpy(g_stats[g_stats_count].domain, domain, MAX_DOMAIN_LEN - 1);
        g_stats[g_stats_count].count = 1;
        g_stats[g_stats_count].flags = flags;
        g_stats_count++;
    }
}

/* Print top queried domains */
void print_stats() {
    printf("\n%s========== SESSION STATISTICS ==========%s\n", COLOR_CYAN, COLOR_RESET);
    printf("Total queries: %d\n", g_total_queries);
    printf("Total alerts:  %s%d%s\n", g_total_alerts > 0 ? COLOR_RED : COLOR_GREEN,
           g_total_alerts, COLOR_RESET);
    printf("Unique domains: %d\n\n", g_stats_count);

    /* Sort by count (simple bubble sort) */
    for (int i = 0; i < g_stats_count - 1; i++) {
        for (int j = 0; j < g_stats_count - i - 1; j++) {
            if (g_stats[j].count < g_stats[j + 1].count) {
                domain_stats temp = g_stats[j];
                g_stats[j] = g_stats[j + 1];
                g_stats[j + 1] = temp;
            }
        }
    }

    printf("Top 15 Queried Domains:\n");
    printf("%-6s %-50s %s\n", "Count", "Domain", "Flags");
    printf("----------------------------------------------------------\n");

    int shown = 0;
    for (int i = 0; i < g_stats_count && shown < 15; i++) {
        char flags[64] = "";
        if (g_stats[i].flags & ALERT_DGA) strcat(flags, "[DGA] ");
        if (g_stats[i].flags & ALERT_EXFIL) strcat(flags, "[EXFIL] ");
        if (g_stats[i].flags & ALERT_TUNNEL) strcat(flags, "[TUNNEL] ");
        if (g_stats[i].flags & ALERT_SUSPECT) strcat(flags, "[SUS-TLD] ");

        const char* color = strlen(flags) > 0 ? COLOR_RED : COLOR_RESET;
        printf("%s%-6d %-50s %s%s\n", color, g_stats[i].count,
               g_stats[i].domain, flags, COLOR_RESET);
        shown++;
    }
}

/* ==================== DNS PARSING ==================== */

const char* get_query_type(unsigned short qtype) {
    switch(qtype) {
        case 1:   return "A";
        case 28:  return "AAAA";
        case 5:   return "CNAME";
        case 15:  return "MX";
        case 2:   return "NS";
        case 12:  return "PTR";
        case 6:   return "SOA";
        case 16:  return "TXT";
        case 33:  return "SRV";
        case 65:  return "HTTPS";
        case 255: return "ANY";
        default:  return "?";
    }
}

int parse_dns_name(const unsigned char* dns_data, int dns_len, int offset,
                   char* name_out, int max_len) {
    int name_pos = 0;
    int original_offset = offset;
    int jumped = 0;
    int jump_count = 0;

    while (offset < dns_len && jump_count < 20) {
        unsigned char len = dns_data[offset];

        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= dns_len) break;
            int pointer = ((len & 0x3F) << 8) | dns_data[offset + 1];
            if (!jumped) original_offset = offset + 2;
            offset = pointer;
            jumped = 1;
            jump_count++;
            continue;
        }

        if (len == 0) {
            if (!jumped) original_offset = offset + 1;
            break;
        }

        offset++;
        if (offset + len > dns_len) break;

        if (name_pos > 0 && name_pos < max_len - 1) {
            name_out[name_pos++] = '.';
        }

        for (int i = 0; i < len && name_pos < max_len - 1; i++) {
            name_out[name_pos++] = dns_data[offset + i];
        }
        offset += len;
    }

    name_out[name_pos] = '\0';
    return original_offset;
}

/* ==================== PACKET PROCESSING ==================== */

void process_dns_packet(const unsigned char* packet, int len) {
    if (len < 54) return;

    ethernet_header* eth = (ethernet_header*)packet;
    if (ntohs(eth->ethertype) != 0x0800) return;

    ip_header* ip = (ip_header*)(packet + 14);
    int ip_header_len = (ip->version_ihl & 0x0F) * 4;

    if (ip->protocol != 17) return; /* UDP only */

    udp_header* udp = (udp_header*)(packet + 14 + ip_header_len);
    unsigned short dest_port = ntohs(udp->dest_port);

    if (dest_port != 53) return;

    const unsigned char* dns_data = (unsigned char*)(packet + 14 + ip_header_len + 8);
    int dns_len = len - 14 - ip_header_len - 8;

    if (dns_len < 12) return;

    dns_header* dns = (dns_header*)dns_data;
    int question_count = ntohs(dns->questions);

    if (ntohs(dns->flags) & 0x8000) return; /* Skip responses */

    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    int offset = 12;
    for (int i = 0; i < question_count && offset < dns_len; i++) {
        char domain[MAX_DOMAIN_LEN];
        offset = parse_dns_name(dns_data, dns_len, offset, domain, sizeof(domain));

        if (offset + 4 > dns_len) break;

        unsigned short qtype = (dns_data[offset] << 8) | dns_data[offset + 1];
        offset += 4;

        g_total_queries++;

        /* Analyze for threats */
        int alert_flags = 0;
        char alerts[256] = "";

        if (is_dga_domain(domain)) {
            alert_flags |= ALERT_DGA;
            strcat(alerts, " [DGA?]");
            g_total_alerts++;
        }
        if (is_exfil_domain(domain)) {
            alert_flags |= ALERT_EXFIL;
            strcat(alerts, " [EXFIL?]");
            g_total_alerts++;
        }
        if (is_tunnel_domain(domain)) {
            alert_flags |= ALERT_TUNNEL;
            strcat(alerts, " [TUNNEL?]");
            g_total_alerts++;
        }
        if (has_suspect_tld(domain)) {
            alert_flags |= ALERT_SUSPECT;
            strcat(alerts, " [SUS-TLD]");
            g_total_alerts++;
        }

        update_stats(domain, alert_flags);

        /* Color output based on alerts */
        const char* color = COLOR_RESET;
        if (alert_flags & (ALERT_DGA | ALERT_TUNNEL | ALERT_EXFIL)) {
            color = COLOR_RED;
        } else if (alert_flags & ALERT_SUSPECT) {
            color = COLOR_YELLOW;
        }

        printf("%s[%s] %-6s %s%s%s\n", color, time_str, get_query_type(qtype),
               domain, alerts, COLOR_RESET);

        /* Log to file */
        if (g_logfile) {
            fprintf(g_logfile, "%s,%s,%s,%d\n", time_str, get_query_type(qtype),
                    domain, alert_flags);
            fflush(g_logfile);
        }
    }

    fflush(stdout);
}

void process_tcp_packet(const unsigned char* packet, int len) {
    if (len < 54) return;

    ethernet_header* eth = (ethernet_header*)packet;
    if (ntohs(eth->ethertype) != 0x0800) return;

    ip_header* ip = (ip_header*)(packet + 14);
    int ip_header_len = (ip->version_ihl & 0x0F) * 4;

    if (ip->protocol != 6) return; /* TCP only */

    tcp_header* tcp = (tcp_header*)(packet + 14 + ip_header_len);
    unsigned short dest_port = ntohs(tcp->dest_port);

    /* Only check SYN packets (new connections) to port 443 */
    if (dest_port != 443) return;
    if ((tcp->flags & 0x02) == 0) return; /* SYN flag */

    char dest_ip[16];
    ip_to_str(ip->dest_addr, dest_ip);

    if (is_doh_server(dest_ip)) {
        time_t now = time(NULL);
        struct tm* tm_info = localtime(&now);
        char time_str[16];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

        printf("%s[%s] [DoH]  → %s (%s DNS - encrypted)%s\n",
               COLOR_MAGENTA, time_str, dest_ip, get_doh_provider(dest_ip), COLOR_RESET);

        if (g_logfile) {
            fprintf(g_logfile, "%s,DoH,%s,0\n", time_str, dest_ip);
            fflush(g_logfile);
        }
    }
}

void process_packet(const unsigned char* packet, int len) {
    process_dns_packet(packet, len);
    process_tcp_packet(packet, len);
}

/* ==================== INTERFACE HANDLING ==================== */

void list_interfaces(pcap_if_t* alldevs) {
    printf("\n%sAvailable interfaces:%s\n", COLOR_CYAN, COLOR_RESET);
    printf("----------------------------------------\n");
    int i = 0;
    for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s\n", ++i, d->name);
        if (d->description) {
            printf("   %s%s%s\n", COLOR_DIM, d->description, COLOR_RESET);
        }
    }
    printf("----------------------------------------\n");
}

/* ==================== SIGNAL HANDLING ==================== */

volatile int g_running = 1;
pcap_t* g_handle = NULL;  /* Global handle for signal handler */

BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        g_running = 0;
        if (g_handle) {
            pcap_breakloop(g_handle);  /* Interrupt blocking pcap call */
        }
        return TRUE;
    }
    return FALSE;
}

/* ==================== MAIN ==================== */

void print_banner() {
    printf("\n");
    printf("%s", COLOR_RED);
    printf("  ____  _   _ ____    ____                   \n");
    printf(" |  _ \\| \\ | / ___|  / ___| _ __  _   _    \n");
    printf(" | | | |  \\| \\___ \\  \\___ \\| '_ \\| | | | \n");
    printf(" | |_| | |\\  |___) |  ___) | |_) | |_| |   \n");
    printf(" |____/|_| \\_|____/  |____/| .__/ \\__, |  \n");
    printf("                           |_|    |___/    \n");
    printf("%s", COLOR_RESET);
    printf("%s         +===========================+%s\n", COLOR_RED, COLOR_RESET);
    printf("%s         |   RED TEAM EDITION v2.0   |%s\n", COLOR_RED, COLOR_RESET);
    printf("%s         +===========================+%s\n", COLOR_RED, COLOR_RESET);
    printf("\n");
    printf(" %s[*]%s DNS Query Monitoring\n", COLOR_GREEN, COLOR_RESET);
    printf(" %s[*]%s DGA Detection (Domain Generation Algorithm)\n", COLOR_GREEN, COLOR_RESET);
    printf(" %s[*]%s DNS Exfiltration Detection\n", COLOR_GREEN, COLOR_RESET);
    printf(" %s[*]%s DNS Tunneling Detection\n", COLOR_GREEN, COLOR_RESET);
    printf(" %s[*]%s DoH (Encrypted DNS) Detection\n", COLOR_GREEN, COLOR_RESET);
    printf(" %s[*]%s Suspicious TLD Alerting\n", COLOR_GREEN, COLOR_RESET);
    printf("\n");
}

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_t* handle;

    enable_colors();
    print_banner();

    /* Set up Ctrl+C handler */
    SetConsoleCtrlHandler(console_handler, TRUE);

    /* Open log file */
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char logname[64];
    CreateDirectory("logs", NULL);  /* Create logs folder if it doesn't exist */
    strftime(logname, sizeof(logname), "logs/dns_spy_%Y%m%d_%H%M%S.csv", tm_info);
    g_logfile = fopen(logname, "w");
    if (g_logfile) {
        fprintf(g_logfile, "time,type,domain,alerts\n");
        printf(" %s[+]%s Logging to: %s%s%s\n\n", COLOR_GREEN, COLOR_RESET,
               COLOR_CYAN, logname, COLOR_RESET);
    }

    /* Get all network interfaces */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "%sError finding devices: %s%s\n", COLOR_RED, errbuf, COLOR_RESET);
        fprintf(stderr, "\nMake sure:\n");
        fprintf(stderr, "  1. Npcap is installed\n");
        fprintf(stderr, "  2. You're running as Administrator\n");
        return 1;
    }

    if (alldevs == NULL) {
        fprintf(stderr, "%sNo interfaces found. Run as Administrator.%s\n", COLOR_RED, COLOR_RESET);
        return 1;
    }

    /* Get interface from command line or prompt */
    int choice;
    if (argc >= 2) {
        choice = atoi(argv[1]);
    } else {
        list_interfaces(alldevs);
        printf("Select interface number: ");
        if (scanf("%d", &choice) != 1 || choice < 1) {
            fprintf(stderr, "Invalid selection\n");
            pcap_freealldevs(alldevs);
            return 1;
        }
    }

    /* Find selected interface */
    pcap_if_t* selected = alldevs;
    for (int i = 1; i < choice && selected != NULL; i++) {
        selected = selected->next;
    }

    if (selected == NULL) {
        fprintf(stderr, "Invalid interface number\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf(" %s[+]%s Interface: %s%s%s\n", COLOR_GREEN, COLOR_RESET,
           COLOR_CYAN, selected->description ? selected->description : selected->name, COLOR_RESET);
    printf(" %s[+]%s Press Ctrl+C to stop and view statistics\n\n", COLOR_GREEN, COLOR_RESET);

    printf("%s%-10s %-6s %s%s\n", COLOR_DIM, "TIME", "TYPE", "DOMAIN", COLOR_RESET);
    printf("%s------------------------------------------------------------%s\n",
           COLOR_DIM, COLOR_RESET);

    /* Open the device for capturing */
    handle = pcap_open_live(
        selected->name,
        65535,
        1,
        1000,
        errbuf
    );

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    g_handle = handle;  /* Set global for signal handler */

    /* Set filter for DNS (port 53) and HTTPS (port 443 for DoH detection) */
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "udp port 53 or (tcp port 443 and tcp[tcpflags] & tcp-syn != 0)", 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(handle));
    } else {
        pcap_setfilter(handle, &filter);
        pcap_freecode(&filter);
    }

    pcap_freealldevs(alldevs);

    /* Capture loop */
    struct pcap_pkthdr* header;
    const unsigned char* packet;
    int result;

    while (g_running && (result = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (result == 0) continue;
        process_packet(packet, header->len);
    }

    pcap_close(handle);

    /* Print statistics on exit */
    print_stats();

    if (g_logfile) {
        fclose(g_logfile);
        printf("\n%s[+] Log saved to: %s%s\n", COLOR_GREEN, logname, COLOR_RESET);
    }

    return 0;
}
