#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>

#define SEC(NAME) __attribute__((section(NAME), used))

// Helper functions
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *) BPF_FUNC_map_lookup_elem;

#define bpf_htons(x) ((__be16)___constant_swab16((x)))

// Структура ключа для LPM Trie
struct lpm_key {
    __u32 prefixlen;
    __u32 ip;
};

// Определение карты через описание в ELF секции
struct bpf_map_def {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
    __u32 map_flags;
};

struct bpf_map_def SEC("maps") ip_map = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_key),
    .value_size = sizeof(__u8),
    .max_entries = 500000,
    .map_flags = BPF_F_NO_PREALLOC,
};

SEC("xdp")
int ip_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
        
    struct lpm_key key = {
        .prefixlen = 32,
        .ip = ip->saddr
    };
    
    __u8 *value = bpf_map_lookup_elem(&ip_map, &key);
    if (value) {
        return *value ? XDP_PASS : XDP_DROP;
    }
    
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
