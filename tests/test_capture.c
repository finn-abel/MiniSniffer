#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define capture_start capture_start_mocked
#define capture_list_interfaces capture_list_interfaces_mocked
#define pcap_close test_pcap_close
#define pcap_datalink test_pcap_datalink
#define pcap_findalldevs test_pcap_findalldevs
#define pcap_freealldevs test_pcap_freealldevs
#define pcap_geterr test_pcap_geterr
#define pcap_dump test_pcap_dump
#define pcap_dump_close test_pcap_dump_close
#define pcap_dump_fopen test_pcap_dump_fopen
#define pcap_next_ex test_pcap_next_ex
#define pcap_open_offline test_pcap_open_offline
#define pcap_open_live test_pcap_open_live
#include "../src/capture.c"
#undef capture_list_interfaces
#undef capture_start
#undef pcap_close
#undef pcap_datalink
#undef pcap_dump
#undef pcap_dump_close
#undef pcap_dump_fopen
#undef pcap_findalldevs
#undef pcap_freealldevs
#undef pcap_geterr
#undef pcap_next_ex
#undef pcap_open_offline
#undef pcap_open_live

#define TEST_MAX_PACKETS 8

typedef struct {
    int find_result;
    pcap_if_t *devices;
    int open_succeeds;
    int open_offline_succeeds;
    int dump_fopen_succeeds;
    int datalink;
    int next_results[TEST_MAX_PACKETS];
    struct pcap_pkthdr headers[TEST_MAX_PACKETS];
    const unsigned char *packets[TEST_MAX_PACKETS];
    size_t next_count;
    size_t next_index;
    int close_count;
    int free_count;
    int offline_open_count;
    int live_open_count;
    int dump_fopen_count;
    int dump_count;
    int dump_close_count;
    struct pcap_pkthdr dumped_headers[TEST_MAX_PACKETS];
    const unsigned char *dumped_packets[TEST_MAX_PACKETS];
    char error[PCAP_ERRBUF_SIZE];
} FakePcapState;

static FakePcapState fake_pcap;

static void reset_fake_pcap(void) {
    memset(&fake_pcap, 0, sizeof(fake_pcap));
    fake_pcap.open_succeeds = 1;
    fake_pcap.open_offline_succeeds = 1;
    fake_pcap.dump_fopen_succeeds = 1;
    fake_pcap.datalink = DLT_EN10MB;
    snprintf(fake_pcap.error, sizeof(fake_pcap.error), "synthetic pcap error");
}

int test_pcap_findalldevs(pcap_if_t **devices, char *error_buffer) {
    if (fake_pcap.find_result != 0) {
        snprintf(error_buffer, PCAP_ERRBUF_SIZE, "%s", fake_pcap.error);
        return fake_pcap.find_result;
    }

    *devices = fake_pcap.devices;
    return 0;
}

void test_pcap_freealldevs(pcap_if_t *devices) {
    (void)devices;
    fake_pcap.free_count++;
}

pcap_t *test_pcap_open_live(const char *device, int snaplen, int promiscuous, int timeout_ms,
                            char *error_buffer) {
    (void)device;
    (void)snaplen;
    (void)promiscuous;
    (void)timeout_ms;

    fake_pcap.live_open_count++;
    if (!fake_pcap.open_succeeds) {
        snprintf(error_buffer, PCAP_ERRBUF_SIZE, "%s", fake_pcap.error);
        return NULL;
    }

    return (pcap_t *)&fake_pcap;
}

pcap_t *test_pcap_open_offline(const char *path, char *error_buffer) {
    (void)path;

    fake_pcap.offline_open_count++;
    if (!fake_pcap.open_offline_succeeds) {
        snprintf(error_buffer, PCAP_ERRBUF_SIZE, "%s", fake_pcap.error);
        return NULL;
    }

    return (pcap_t *)&fake_pcap;
}

int test_pcap_datalink(pcap_t *handle) {
    assert(handle == (pcap_t *)&fake_pcap);
    return fake_pcap.datalink;
}

int test_pcap_next_ex(pcap_t *handle, struct pcap_pkthdr **header, const unsigned char **packet) {
    size_t index;
    int result;

    assert(handle == (pcap_t *)&fake_pcap);
    if (fake_pcap.next_index >= fake_pcap.next_count) {
        return -2;
    }

    index = fake_pcap.next_index++;
    result = fake_pcap.next_results[index];
    if (result == 1) {
        *header = &fake_pcap.headers[index];
        *packet = fake_pcap.packets[index];
    }
    return result;
}

char *test_pcap_geterr(pcap_t *handle) {
    assert(handle == (pcap_t *)&fake_pcap);
    return fake_pcap.error;
}

void test_pcap_close(pcap_t *handle) {
    assert(handle == (pcap_t *)&fake_pcap);
    fake_pcap.close_count++;
}

pcap_dumper_t *test_pcap_dump_fopen(pcap_t *handle, FILE *file) {
    assert(handle == (pcap_t *)&fake_pcap);
    assert(file != NULL);
    fake_pcap.dump_fopen_count++;
    if (!fake_pcap.dump_fopen_succeeds) {
        return NULL;
    }
    return (pcap_dumper_t *)&fake_pcap;
}

void test_pcap_dump(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    size_t index;

    assert(user == (u_char *)&fake_pcap);
    assert(header != NULL);
    assert(packet != NULL);
    assert(fake_pcap.dump_count < TEST_MAX_PACKETS);
    index = (size_t)fake_pcap.dump_count;
    fake_pcap.dumped_headers[index] = *header;
    fake_pcap.dumped_packets[index] = packet;
    fake_pcap.dump_count++;
}

void test_pcap_dump_close(pcap_dumper_t *dumper) {
    assert(dumper == (pcap_dumper_t *)&fake_pcap);
    fake_pcap.dump_close_count++;
}

static pcap_if_t make_device(char *name, unsigned int flags, pcap_addr_t *addresses,
                             pcap_if_t *next) {
    pcap_if_t device;

    memset(&device, 0, sizeof(device));
    device.name = name;
    device.flags = flags;
    device.addresses = addresses;
    device.next = next;
    return device;
}

static pcap_addr_t make_address(struct sockaddr *address, pcap_addr_t *next) {
    pcap_addr_t entry;

    memset(&entry, 0, sizeof(entry));
    entry.addr = address;
    entry.next = next;
    return entry;
}

static AppConfig make_capture_config(const char *interface_name) {
    AppConfig config;

    config_init_defaults(&config);
    snprintf(config.interface_name, sizeof(config.interface_name), "%s", interface_name);
    return config;
}

static void set_single_device(pcap_if_t *device) {
    fake_pcap.devices = device;
    device->next = NULL;
}

static void capture_interface_list_output(char *buffer, size_t buffer_size) {
    FILE *capture;
    size_t bytes_read;

    assert(buffer != NULL);
    assert(buffer_size > 0);

    capture = tmpfile();
    assert(capture != NULL);
    assert(capture_list_interfaces_mocked(capture) == 0);
    rewind(capture);
    bytes_read = fread(buffer, 1, buffer_size - 1, capture);
    buffer[bytes_read] = '\0';
    assert(!ferror(capture));
    fclose(capture);
}

static size_t build_tcp_packet(unsigned char *packet, size_t packet_capacity, uint32_t sequence,
                               const uint8_t *payload, size_t payload_length) {
    const size_t ethernet_length = 14;
    const size_t ipv4_length = 20;
    const size_t tcp_length = 20;
    const size_t packet_length = ethernet_length + ipv4_length + tcp_length + payload_length;
    size_t ip = ethernet_length;
    size_t tcp = ethernet_length + ipv4_length;
    uint16_t total_length = (uint16_t)(ipv4_length + tcp_length + payload_length);

    assert(packet_length <= packet_capacity);
    assert(total_length >= ipv4_length + tcp_length);
    memset(packet, 0, packet_length);

    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[ip] = 0x45;
    packet[ip + 2] = (uint8_t)(total_length >> 8);
    packet[ip + 3] = (uint8_t)total_length;
    packet[ip + 8] = 64;
    packet[ip + 9] = 6;
    packet[ip + 12] = 10;
    packet[ip + 15] = 1;
    packet[ip + 16] = 10;
    packet[ip + 19] = 2;

    packet[tcp] = 0xc3;
    packet[tcp + 1] = 0x50;
    packet[tcp + 3] = 80;
    packet[tcp + 4] = (uint8_t)(sequence >> 24);
    packet[tcp + 5] = (uint8_t)(sequence >> 16);
    packet[tcp + 6] = (uint8_t)(sequence >> 8);
    packet[tcp + 7] = (uint8_t)sequence;
    packet[tcp + 12] = 0x50;
    packet[tcp + 13] = 0x18;

    if (payload_length != 0) {
        memcpy(packet + ethernet_length + ipv4_length + tcp_length, payload, payload_length);
    }
    return packet_length;
}

static size_t build_ipv4_fragment_packet(unsigned char *packet, size_t packet_capacity,
                                         uint16_t identification, size_t fragment_offset,
                                         int more_fragments, const uint8_t *fragment_payload,
                                         size_t fragment_payload_length) {
    const size_t ethernet_length = 14;
    const size_t ipv4_length = 20;
    const size_t packet_length = ethernet_length + ipv4_length + fragment_payload_length;
    size_t ip = ethernet_length;
    uint16_t total_length = (uint16_t)(ipv4_length + fragment_payload_length);
    uint16_t fragment_field = (uint16_t)(fragment_offset / 8);

    assert(packet_length <= packet_capacity);
    assert(fragment_offset % 8 == 0);
    memset(packet, 0, packet_length);

    if (more_fragments) {
        fragment_field |= 0x2000;
    }
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[ip] = 0x45;
    packet[ip + 2] = (uint8_t)(total_length >> 8);
    packet[ip + 3] = (uint8_t)total_length;
    packet[ip + 4] = (uint8_t)(identification >> 8);
    packet[ip + 5] = (uint8_t)identification;
    packet[ip + 6] = (uint8_t)(fragment_field >> 8);
    packet[ip + 7] = (uint8_t)fragment_field;
    packet[ip + 8] = 64;
    packet[ip + 9] = 6;
    packet[ip + 12] = 10;
    packet[ip + 15] = 1;
    packet[ip + 16] = 10;
    packet[ip + 19] = 2;
    memcpy(packet + ethernet_length + ipv4_length, fragment_payload, fragment_payload_length);
    return packet_length;
}

static size_t build_tcp_datagram_payload(unsigned char *payload, size_t payload_capacity,
                                         const uint8_t *app_payload, size_t app_payload_length) {
    const size_t tcp_length = 20;
    size_t payload_length = tcp_length + app_payload_length;

    assert(payload_length <= payload_capacity);
    memset(payload, 0, payload_length);
    payload[0] = 0xc3;
    payload[1] = 0x50;
    payload[3] = 80;
    payload[12] = 0x50;
    payload[13] = 0x18;
    memcpy(payload + tcp_length, app_payload, app_payload_length);
    return payload_length;
}

static void queue_packet(size_t index, const unsigned char *packet, size_t length, long seconds) {
    assert(index < TEST_MAX_PACKETS);
    fake_pcap.next_results[index] = 1;
    fake_pcap.packets[index] = packet;
    fake_pcap.headers[index].caplen = (bpf_u_int32)length;
    fake_pcap.headers[index].len = (bpf_u_int32)length;
    fake_pcap.headers[index].ts.tv_sec = seconds;
    fake_pcap.headers[index].ts.tv_usec = 123456;
    if (fake_pcap.next_count <= index) {
        fake_pcap.next_count = index + 1;
    }
}

static void test_capture_start_rejects_null_config(void) {
    assert(capture_start_mocked(NULL, NULL) != 0);
}

static void test_capture_device_helpers(void) {
    char destination[16];
    struct sockaddr ipv4;
    struct sockaddr ipv6;
    pcap_addr_t ipv4_entry;
    pcap_addr_t ipv6_entry;
    pcap_addr_t null_entry;
    char en_name[] = "en0";
    pcap_if_t device;

    memset(&ipv4, 0, sizeof(ipv4));
    memset(&ipv6, 0, sizeof(ipv6));
    ipv4.sa_family = AF_INET;
    ipv6.sa_family = AF_INET6;
    ipv4_entry = make_address(&ipv4, NULL);
    ipv6_entry = make_address(&ipv6, &ipv4_entry);
    null_entry = make_address(NULL, &ipv6_entry);
    device = make_device(en_name, 0, &null_entry, NULL);

    assert(has_ipv4_address(&device));
    assert(has_ipv6_address(&device));
    assert(!is_loopback_device(&device));
    assert(is_preferred_default_device(&device));
    device.flags = PCAP_IF_LOOPBACK;
    assert(is_loopback_device(&device));
    assert(!is_preferred_default_device(&device));

    assert(!is_apple_internal_device_name(NULL));
    assert(is_apple_internal_device_name("ap1"));
    assert(is_apple_internal_device_name("awdl0"));
    assert(is_apple_internal_device_name("llw0"));
    assert(is_apple_internal_device_name("utun2"));
    assert(!is_apple_internal_device_name("eth0"));

    assert(copy_device_name(destination, sizeof(destination), "en0") == 0);
    assert(strcmp(destination, "en0") == 0);
    assert(copy_device_name(NULL, sizeof(destination), "en0") != 0);
    assert(copy_device_name(destination, sizeof(destination), NULL) != 0);
    assert(copy_device_name(destination, 0, "en0") != 0);
    assert(copy_device_name(destination, 2, "en0") != 0);
}

static void test_choose_default_device_paths(void) {
    char selected[16];
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct sockaddr ipv4;
    pcap_addr_t address;
    char loop_name[] = "lo0";
    char apple_name[] = "awdl0";
    char generic_name[] = "eth0";
    char preferred_name[] = "en7";
    pcap_if_t preferred;
    pcap_if_t generic;
    pcap_if_t apple;
    pcap_if_t loop;

    memset(&ipv4, 0, sizeof(ipv4));
    ipv4.sa_family = AF_INET;
    address = make_address(&ipv4, NULL);
    loop = make_device(loop_name, PCAP_IF_LOOPBACK, NULL, NULL);
    apple = make_device(apple_name, 0, NULL, &loop);
    generic = make_device(generic_name, 0, &address, &apple);
    preferred = make_device(preferred_name, 0, &address, &generic);

    reset_fake_pcap();
    fake_pcap.devices = &preferred;
    assert(choose_default_device(selected, sizeof(selected), error_buffer) == 0);
    assert(strcmp(selected, "en7") == 0);

    reset_fake_pcap();
    fake_pcap.devices = &generic;
    assert(choose_default_device(selected, sizeof(selected), error_buffer) == 0);
    assert(strcmp(selected, "eth0") == 0);

    generic.addresses = NULL;
    reset_fake_pcap();
    fake_pcap.devices = &generic;
    assert(choose_default_device(selected, sizeof(selected), error_buffer) == 0);
    assert(strcmp(selected, "eth0") == 0);

    reset_fake_pcap();
    fake_pcap.devices = &apple;
    assert(choose_default_device(selected, sizeof(selected), error_buffer) == 0);
    assert(strcmp(selected, "awdl0") == 0);

    reset_fake_pcap();
    fake_pcap.devices = &loop;
    assert(choose_default_device(selected, sizeof(selected), error_buffer) != 0);

    reset_fake_pcap();
    fake_pcap.find_result = -1;
    assert(choose_default_device(selected, sizeof(selected), error_buffer) != 0);

    reset_fake_pcap();
    fake_pcap.devices = &preferred;
    assert(choose_default_device(selected, 2, error_buffer) != 0);
}

static void test_interface_exists_paths(void) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    char first_name[] = "en0";
    char second_name[] = "en1";
    pcap_if_t second = make_device(second_name, 0, NULL, NULL);
    pcap_if_t first = make_device(first_name, 0, NULL, &second);

    reset_fake_pcap();
    fake_pcap.devices = &first;
    assert(interface_exists("en1", error_buffer));
    assert(!interface_exists("en9", error_buffer));

    reset_fake_pcap();
    fake_pcap.find_result = -1;
    assert(!interface_exists("en0", error_buffer));
}

static void test_capture_list_interfaces_prints_hints(void) {
    char output[1024];
    struct sockaddr ipv4;
    struct sockaddr ipv6;
    pcap_addr_t ipv4_entry;
    pcap_addr_t ipv6_entry;
    char en_name[] = "en0";
    char loop_name[] = "lo0";
    char awdl_name[] = "awdl0";
    char en_description[] = "Wi-Fi";
    pcap_if_t awdl;
    pcap_if_t loop;
    pcap_if_t en;

    memset(&ipv4, 0, sizeof(ipv4));
    memset(&ipv6, 0, sizeof(ipv6));
    ipv4.sa_family = AF_INET;
    ipv6.sa_family = AF_INET6;
    ipv4_entry = make_address(&ipv4, NULL);
    ipv6_entry = make_address(&ipv6, NULL);
    awdl = make_device(awdl_name, 0, &ipv6_entry, NULL);
    loop = make_device(loop_name, PCAP_IF_LOOPBACK, NULL, &awdl);
    en = make_device(en_name, 0, &ipv4_entry, &loop);
    en.description = en_description;

    reset_fake_pcap();
    fake_pcap.devices = &en;
    capture_interface_list_output(output, sizeof(output));

    TEST_ASSERT_CONTAINS(output, "Capture interfaces:\n");
    TEST_ASSERT_CONTAINS(output, "* en0 - Wi-Fi [default-candidate, ipv4]\n");
    TEST_ASSERT_CONTAINS(output, "  lo0 - (no description) [loopback]\n");
    TEST_ASSERT_CONTAINS(output, "  awdl0 - (no description) [internal, ipv6]\n");
    assert(fake_pcap.free_count == 1);
}

static void test_capture_setup_failures(void) {
    char device_name[] = "en-test";
    pcap_if_t device = make_device(device_name, 0, NULL, NULL);
    AppConfig config;

    reset_fake_pcap();
    fake_pcap.find_result = -1;
    config_init_defaults(&config);
    assert(capture_start_mocked(&config, NULL) != 0);

    reset_fake_pcap();
    config = make_capture_config("missing");
    assert(capture_start_mocked(&config, NULL) != 0);

    reset_fake_pcap();
    set_single_device(&device);
    fake_pcap.open_succeeds = 0;
    snprintf(fake_pcap.error, sizeof(fake_pcap.error), "Permission denied");
    config = make_capture_config(device_name);
    assert(capture_start_mocked(&config, NULL) != 0);

    reset_fake_pcap();
    set_single_device(&device);
    fake_pcap.datalink = 999999;
    config = make_capture_config(device_name);
    assert(capture_start_mocked(&config, NULL) != 0);
    assert(fake_pcap.close_count == 1);

    reset_fake_pcap();
    set_single_device(&device);
    config = make_capture_config(device_name);
    config.reassemble = true;
    config.max_flows = 0;
    assert(capture_start_mocked(&config, NULL) != 0);
    assert(fake_pcap.close_count == 1);

    reset_fake_pcap();
    set_single_device(&device);
    config = make_capture_config(device_name);
    config.logging_enabled = 1;
    snprintf(config.log_path, sizeof(config.log_path), "/no/such/directory/capture.csv");
    assert(capture_start_mocked(&config, NULL) != 0);
    assert(fake_pcap.close_count == 1);
}

static void test_capture_loop_handles_timeout_error_and_bad_packet(void) {
    char device_name[] = "en-test";
    pcap_if_t device = make_device(device_name, 0, NULL, NULL);
    AppConfig config = make_capture_config(device_name);

    reset_fake_pcap();
    set_single_device(&device);
    fake_pcap.next_results[0] = 0;
    fake_pcap.next_results[1] = -2;
    fake_pcap.next_count = 2;
    assert(capture_start_mocked(&config, NULL) == 0);
    assert(fake_pcap.close_count == 1);

    reset_fake_pcap();
    set_single_device(&device);
    fake_pcap.next_results[0] = -1;
    fake_pcap.next_count = 1;
    assert(capture_start_mocked(&config, NULL) != 0);
    assert(fake_pcap.close_count == 1);

    reset_fake_pcap();
    set_single_device(&device);
    fake_pcap.next_results[0] = 1;
    fake_pcap.headers[0].caplen = 1;
    fake_pcap.packets[0] = NULL;
    fake_pcap.next_count = 1;
    assert(capture_start_mocked(&config, NULL) != 0);
    assert(fake_pcap.close_count == 1);
}

static void test_capture_processes_and_filters_packets(void) {
    static const uint8_t http_request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    unsigned char packet[256];
    size_t packet_length =
        build_tcp_packet(packet, sizeof(packet), 100, http_request, sizeof(http_request) - 1);
    char device_name[] = "en-test";
    pcap_if_t device = make_device(device_name, 0, NULL, NULL);
    AppConfig config = make_capture_config(device_name);
    PacketStats stats;

    reset_fake_pcap();
    set_single_device(&device);
    queue_packet(0, packet, packet_length, 10);
    config.max_packets = 1;
    config.decode_app = true;
    config.payload_display_enabled = 1;
    config.payload_preview_bytes = 8;
    stats_init(&stats);
    assert(capture_start_mocked(&config, &stats) == 0);
    assert(stats.total_packets == 1);
    assert(stats.tcp_packets == 1);

    reset_fake_pcap();
    set_single_device(&device);
    queue_packet(0, packet, packet_length, 10);
    fake_pcap.next_results[1] = -2;
    fake_pcap.next_count = 2;
    config.filter_protocol_enabled = 1;
    config.filter_protocol = PROTO_UDP;
    stats_init(&stats);
    assert(capture_start_mocked(&config, &stats) == 0);
    assert(stats.total_packets == 0);
}

static void test_capture_reads_offline_without_interface_selection(void) {
    static const uint8_t http_request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    unsigned char packet[256];
    size_t packet_length =
        build_tcp_packet(packet, sizeof(packet), 100, http_request, sizeof(http_request) - 1);
    AppConfig config;
    PacketStats stats;

    reset_fake_pcap();
    fake_pcap.find_result = -1;
    queue_packet(0, packet, packet_length, 21);
    config_init_defaults(&config);
    config.read_path_enabled = true;
    snprintf(config.read_path, sizeof(config.read_path), "%s", "/tmp/input.pcap");
    config.max_packets = 1;

    stats_init(&stats);
    assert(capture_start_mocked(&config, &stats) == 0);
    assert(stats.total_packets == 1);
    assert(fake_pcap.offline_open_count == 1);
    assert(fake_pcap.live_open_count == 0);
    assert(fake_pcap.free_count == 0);
    assert(fake_pcap.close_count == 1);
}

static void test_capture_writes_only_displayed_packets_to_pcap(void) {
    static const uint8_t http_request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    unsigned char packet[256];
    size_t packet_length =
        build_tcp_packet(packet, sizeof(packet), 100, http_request, sizeof(http_request) - 1);
    char device_name[] = "en-test";
    char write_path[] = "/tmp/minisniffer_mock_write.pcap";
    pcap_if_t device = make_device(device_name, 0, NULL, NULL);
    AppConfig config = make_capture_config(device_name);
    PacketStats stats;

    reset_fake_pcap();
    set_single_device(&device);
    queue_packet(0, packet, packet_length, 30);
    queue_packet(1, packet, packet_length, 31);
    config.write_path_enabled = true;
    snprintf(config.write_path, sizeof(config.write_path), "%s", write_path);
    config.filter_protocol_enabled = 1;
    config.filter_protocol = PROTO_TCP;
    config.max_packets = 1;
    unlink(write_path);

    stats_init(&stats);
    assert(capture_start_mocked(&config, &stats) == 0);
    assert(stats.total_packets == 1);
    assert(fake_pcap.dump_fopen_count == 1);
    assert(fake_pcap.dump_count == 1);
    assert(fake_pcap.dump_close_count == 1);
    assert(fake_pcap.dumped_headers[0].ts.tv_sec == 30);
    assert(fake_pcap.dumped_headers[0].caplen == packet_length);
    assert(fake_pcap.dumped_packets[0] == packet);
    unlink(write_path);
}

static void test_capture_write_refuses_existing_pcap_file(void) {
    char device_name[] = "en-test";
    char write_path[] = "/tmp/minisniffer_existing_write.pcap";
    pcap_if_t device = make_device(device_name, 0, NULL, NULL);
    AppConfig config = make_capture_config(device_name);
    FILE *file;

    reset_fake_pcap();
    set_single_device(&device);
    config.write_path_enabled = true;
    snprintf(config.write_path, sizeof(config.write_path), "%s", write_path);
    file = fopen(write_path, "w");
    assert(file != NULL);
    fclose(file);

    assert(capture_start_mocked(&config, NULL) != 0);
    assert(fake_pcap.dump_fopen_count == 0);
    assert(fake_pcap.close_count == 1);
    unlink(write_path);
}

static void test_capture_reassembles_split_http_and_logs(void) {
    static const uint8_t first_payload[] = "GET / HTTP/1.1\r\nHost: ex";
    static const uint8_t second_payload[] = "ample.com\r\n\r\n";
    static const uint8_t third_payload[] = "body";
    unsigned char first_packet[256];
    unsigned char second_packet[256];
    unsigned char third_packet[256];
    size_t first_length;
    size_t second_length;
    size_t third_length;
    char device_name[] = "en-test";
    pcap_if_t device = make_device(device_name, 0, NULL, NULL);
    AppConfig config = make_capture_config(device_name);
    PacketStats stats;
    const char *log_path = "/tmp/minisniffer_capture_test.csv";

    first_length = build_tcp_packet(first_packet, sizeof(first_packet), 100, first_payload,
                                    sizeof(first_payload) - 1);
    second_length = build_tcp_packet(second_packet, sizeof(second_packet),
                                     100 + (uint32_t)(sizeof(first_payload) - 1), second_payload,
                                     sizeof(second_payload) - 1);
    third_length = build_tcp_packet(third_packet, sizeof(third_packet),
                                    100 + (uint32_t)(sizeof(first_payload) - 1) +
                                        (uint32_t)(sizeof(second_payload) - 1),
                                    third_payload, sizeof(third_payload) - 1);

    reset_fake_pcap();
    set_single_device(&device);
    queue_packet(0, first_packet, first_length, 10);
    queue_packet(1, second_packet, second_length, 11);
    queue_packet(2, third_packet, third_length, 12);
    config.max_packets = 3;
    config.decode_app = true;
    config.reassemble = true;
    config.max_flows = 4;
    config.stream_buffer_bytes = 512;
    config.logging_enabled = 1;
    snprintf(config.log_path, sizeof(config.log_path), "%s", log_path);
    unlink(log_path);

    stats_init(&stats);
    assert(capture_start_mocked(&config, &stats) == 0);
    assert(stats.total_packets == 3);
    assert(fake_pcap.close_count == 1);
    assert(access(log_path, F_OK) == 0);
    unlink(log_path);
}

static void test_capture_reassembles_ipv4_fragments_for_app_decode(void) {
    static const uint8_t http_request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    unsigned char datagram_payload[128];
    unsigned char first_packet[128];
    unsigned char second_packet[128];
    size_t datagram_payload_length;
    size_t first_length;
    size_t second_length;
    char device_name[] = "en-test";
    pcap_if_t device = make_device(device_name, 0, NULL, NULL);
    AppConfig config = make_capture_config(device_name);
    PacketStats stats;

    datagram_payload_length =
        build_tcp_datagram_payload(datagram_payload, sizeof(datagram_payload), http_request,
                                   sizeof(http_request) - 1);
    first_length = build_ipv4_fragment_packet(first_packet, sizeof(first_packet), 77, 0, 1,
                                              datagram_payload, 24);
    second_length = build_ipv4_fragment_packet(second_packet, sizeof(second_packet), 77, 24, 0,
                                               datagram_payload + 24, datagram_payload_length - 24);

    reset_fake_pcap();
    set_single_device(&device);
    queue_packet(0, first_packet, first_length, 40);
    queue_packet(1, second_packet, second_length, 41);
    config.max_packets = 2;
    config.decode_app = true;

    stats_init(&stats);
    assert(capture_start_mocked(&config, &stats) == 0);
    assert(stats.total_packets == 2);
    assert(stats.tcp_packets == 2);
    assert(stats.ipv4_fragments_seen == 2);
    assert(stats.ipv4_fragments_reassembled == 1);
    assert(stats.ipv4_fragments_malformed == 0);
    assert(stats.ipv4_fragments_dropped == 0);
}

static void test_capture_static_helpers_and_signal_path(void) {
    struct pcap_pkthdr header;
    PacketInfo packet;
    FlowInfo flow;
    static const uint8_t oversized[] = "ABCDE";

    memset(&packet, 0, sizeof(packet));
    memset(&header, 0, sizeof(header));
    header.ts.tv_sec = 12;
    header.ts.tv_usec = 34;
    set_packet_timestamp(NULL, &header);
    set_packet_timestamp(&packet, NULL);
    set_packet_timestamp(&packet, &header);
    assert(strcmp(packet.timestamp, "12.000034") == 0);

    print_open_live_error("en0", "plain failure");
    print_open_live_error("en0", "permission denied");
    print_open_live_error("en0", "Operation not permitted");

    memset(&flow, 0, sizeof(flow));
    assert(!flow_decode_stream_app(NULL, FLOW_DIR_A_TO_B, &packet));
    assert(!flow_decode_stream_app(&flow, FLOW_DIR_A_TO_B, NULL));
    packet.protocol = PROTO_UDP;
    assert(!flow_decode_stream_app(&flow, FLOW_DIR_A_TO_B, &packet));

    packet.protocol = PROTO_TCP;
    packet.has_tcp_sequence = 1;
    packet.has_payload = 1;
    packet.payload = oversized;
    packet.payload_capture_length = sizeof(oversized) - 1;
    flow.stream_buffer_bytes = 4;
    assert(!flow_decode_stream_app(&flow, FLOW_DIR_A_TO_B, &packet));
    tcp_reassembly_direction_cleanup(&flow.directions[FLOW_DIR_A_TO_B].tcp);

    should_stop = 0;
    handle_sigint(SIGINT);
    assert(should_stop == 1);
}

int main(void) {
    test_capture_start_rejects_null_config();
    test_capture_device_helpers();
    test_choose_default_device_paths();
    test_interface_exists_paths();
    test_capture_list_interfaces_prints_hints();
    test_capture_setup_failures();
    test_capture_loop_handles_timeout_error_and_bad_packet();
    test_capture_processes_and_filters_packets();
    test_capture_reads_offline_without_interface_selection();
    test_capture_writes_only_displayed_packets_to_pcap();
    test_capture_write_refuses_existing_pcap_file();
    test_capture_reassembles_split_http_and_logs();
    test_capture_reassembles_ipv4_fragments_for_app_decode();
    test_capture_static_helpers_and_signal_path();

    printf("All capture tests passed.\n");
    return 0;
}
