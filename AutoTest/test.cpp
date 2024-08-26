// TEST ubpf for Qemu's RSS

#include <iostream>
#include <vector>
#include <cinttypes>

#include "rss.bpf.skeleton.h"

#include "ubpf.h"

/* supported/enabled hash types */
#define VIRTIO_NET_RSS_HASH_TYPE_IPv4 (1 << 0)
#define VIRTIO_NET_RSS_HASH_TYPE_TCPv4 (1 << 1)
#define VIRTIO_NET_RSS_HASH_TYPE_UDPv4 (1 << 2)
#define VIRTIO_NET_RSS_HASH_TYPE_IPv6 (1 << 3)
#define VIRTIO_NET_RSS_HASH_TYPE_TCPv6 (1 << 4)
#define VIRTIO_NET_RSS_HASH_TYPE_UDPv6 (1 << 5)
#define VIRTIO_NET_RSS_HASH_TYPE_IP_EX (1 << 6)
#define VIRTIO_NET_RSS_HASH_TYPE_TCP_EX (1 << 7)
#define VIRTIO_NET_RSS_HASH_TYPE_UDP_EX (1 << 8)

class BpfMapInterface
{
  public:
    virtual ~BpfMapInterface() {}
    virtual void*
    operator[](const void* key)
    {
        return nullptr;
    }
};

class BpfRssConfigMap : public BpfMapInterface
{
    struct rss_config_t
    {
        __u8 redirect;
        __u8 populate_hash;
        __u32 hash_types;
        __u16 indirections_len;
        __u16 default_queue;
    } __attribute__((packed));

  public:
    BpfRssConfigMap() {}
    ~BpfRssConfigMap() {}

    void*
    operator[](const void* key) override
    {
        return reinterpret_cast<void*>(&m_config);
    }

    struct rss_config_t m_config = {
        .redirect = 1,
        .populate_hash = 0,
        .hash_types = 0xff,
        .indirections_len = 128,
        .default_queue = 0,
    };
};

class BpfRssToeplitzMap : public BpfMapInterface
{
#define HASH_CALCULATION_BUFFER_SIZE 36
    struct toeplitz_key_data_t
    {
        __u32 leftmost_32_bits;
        __u8 next_byte[HASH_CALCULATION_BUFFER_SIZE];
    };

  public:
    BpfRssToeplitzMap() {}

    void*
    operator[](const void* key) override
    {
        return reinterpret_cast<void*>(&m_toe);
    }

    struct toeplitz_key_data_t m_toe = {
        .leftmost_32_bits = 0x6d5a56da,
        .next_byte = {0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
                      0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
                      0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa},
    };
};

class BpfRssIndirectionTableMap : public BpfMapInterface
{
  public:
    BpfRssIndirectionTableMap() : m_indirection_table(128, 0) {}

    void*
    operator[](const void* key) override
    {
        return reinterpret_cast<void*>(&m_indirection_table[*reinterpret_cast<const uint32_t*>(key)]);
    }

    std::vector<uint16_t> m_indirection_table;
};

struct TestUserContext
{
    BpfRssConfigMap map_config;
    BpfRssToeplitzMap map_toe;
    BpfRssIndirectionTableMap map_indtbl;
};

uint64_t
do_map_relocation(
    void* user_context,
    const uint8_t* map_data,
    uint64_t map_data_size,
    const char* symbol_name,
    uint64_t symbol_offset,
    uint64_t symbol_size)
{
    // if (symbol_name && *symbol_name) {
    //     struct ubpf_btf_map_desc
    //     {
    //         const char* name;
    //         uint64_t type;
    //         uint64_t key_size;
    //         uint64_t value_size;
    //         uint64_t max_entries;
    //         uint64_t map_flags;
    //     };
    //     auto* btf_map = reinterpret_cast<const struct ubpf_btf_map_desc*>(map_data);
    //     std::cerr << "Map type: " << btf_map->type << " name " << btf_map->name << std::endl;
    //     std::cerr << "Map key: " << btf_map->key_size << std::endl;
    //     std::cerr << "Map val: " << btf_map->value_size << std::endl;
    //     std::cerr << "Map entries: " << btf_map->max_entries << std::endl;
    // }

    auto* ctx = reinterpret_cast<TestUserContext*>(user_context);
    if (std::string(symbol_name) == "tap_rss_map_configurations") {
        return reinterpret_cast<uint64_t>(static_cast<BpfMapInterface*>(&ctx->map_config));
    } else if (std::string(symbol_name) == "tap_rss_map_toeplitz_key") {
        return reinterpret_cast<uint64_t>(static_cast<BpfMapInterface*>(&ctx->map_toe));
    } else if (std::string(symbol_name) == "tap_rss_map_indirection_table") {
        return reinterpret_cast<uint64_t>(static_cast<BpfMapInterface*>(&ctx->map_indtbl));
    } else {
        return reinterpret_cast<uint64_t>(map_data);
    }
}

static void
register_functions(struct ubpf_vm* vm);

int
main(int argc, char** argv)
{
    bool jit = true;

    size_t code_len;
    const void* code = rss_bpf__elf_bytes(&code_len);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/network/verifying-the-rss-hash-calculation
    // 161.142.100.80:1766    Destination
    // 66.9.149.187:2794      Source
    // 0x323e8fc2             IPv4 only
    // 0x51ccc178             IPv4 with TCP
    // Note, that everything noninvolved in the RSS calculation is omitted.
    std::vector<uint8_t> skb_data = {
        // Etheret frame
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, // ip

        // IPv4 header
        0x05, // ip header size
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, // tcp
        0x00, 0x00,
        0x42, 0x09, 0x95, 0xbb, // source ip
        0xa1, 0x8e, 0x64, 0x50, // destination ip

        // TCP header
        0x0a, 0xea, // source port
        0x06, 0xe6, // destination port
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    TestUserContext user_context;
    user_context.map_config.m_config.hash_types = VIRTIO_NET_RSS_HASH_TYPE_IPv4 | VIRTIO_NET_RSS_HASH_TYPE_TCPv4;

    struct ubpf_vm* vm = ubpf_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }

    ubpf_register_data_relocation(vm, &user_context, do_map_relocation);

    register_functions(vm);

    char* errmsg;
    int rv;

    rv = ubpf_load_elf_ex(vm, code, code_len, "tun_rss_steering_prog", &errmsg);

    if (rv < 0) {
        fprintf(stderr, "Failed to load code: %s\n", errmsg);
        free(errmsg);
        ubpf_destroy(vm);
        return 1;
    }

    uint64_t ret;

    if (jit) {
        ubpf_jit_fn fn = ubpf_compile(vm, &errmsg);
        if (fn == NULL) {
            fprintf(stderr, "Failed to compile: %s\n", errmsg);
            free(errmsg);
            return 1;
        }
        ret = fn(skb_data.data(), skb_data.size());
    } else {
        if (ubpf_exec(vm, skb_data.data(), skb_data.size(), &ret) < 0)
            ret = UINT64_MAX;
    }

    printf("0x%" PRIx64 "\n", ret);

    ubpf_destroy(vm);

    return 0;
}

static void* const
ubpf_map_lookup_elem(void* map, const void* key)
{
    return (*reinterpret_cast<BpfMapInterface*>(map))[key];
}

static long const
ubpf_skb_load_bytes_relative(const void* skb, __u32 offset, void* to, __u32 len, __u32 start_header)
{
    const uint8_t* data = reinterpret_cast<const uint8_t*>(skb);
    memcpy(to, data + offset + 14 * start_header, len);

    return 0;
}

static long const
ubpf_trace_printk(const char* fmt, __u32 fmt_size, ...)
{
    va_list argp;
    va_start(argp, fmt_size);
    vfprintf(stderr, fmt, argp);
    va_end(argp);
    return 0;
}
static void
register_functions(struct ubpf_vm* vm)
{
    // static void *(* const bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
    ubpf_register(vm, 1, "bpf_map_lookup_elem", as_external_function_t(reinterpret_cast<void*>(ubpf_map_lookup_elem)));

    // static long (* const bpf_skb_load_bytes_relative)(const void *skb, __u32 offset, void *to, __u32 len, __u32
    // start_header) = (void *) 68;
    ubpf_register(
        vm,
        68,
        "bpf_skb_load_bytes_relative",
        as_external_function_t(reinterpret_cast<void*>(ubpf_skb_load_bytes_relative)));

    // static long (* const bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
    ubpf_register(vm, 6, "bpf_trace_printk", as_external_function_t(reinterpret_cast<void*>(ubpf_trace_printk)));
}
