#undef NDEBUG

#include "nvme/private.h"
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>

#define MTU 64

#ifdef DEBUG_LOG
#define DEBUG_PRINT(...) fprintf(stderr, __VA_ARGS__)
#define HEXDUMP(data, size, prefix) hexdump(data, size, prefix)
#else
#define DEBUG_PRINT(...)
#define HEXDUMP(data, size, prefix)
#endif

static void hexdump(const void *data, size_t size, const char *prefix)
{
    const unsigned char *bytes = (const unsigned char *)data;
    size_t bytes_per_line = 16;

    for (size_t i = 0; i < size; i += bytes_per_line)
    {
        fprintf(stdout, "%s%08zx  ", prefix, i);

        for (size_t j = 0; j < bytes_per_line; ++j)
        {
            if (i + j < size)
            {
                fprintf(stdout, "%02X ", bytes[i + j]);
            }
            else
            {
                fprintf(stdout, "   ");
            }
        }

        fprintf(stdout, " ");

        for (size_t j = 0; j < bytes_per_line; ++j)
        {
            if (i + j < size)
            {
                unsigned char c = bytes[i + j];
                fprintf(stdout, "%c", isprint(c) ? c : '.');
            }
            else
            {
                fprintf(stdout, " ");
            }
        }

        fprintf(stdout, "\n");
    }
}

static uint16_t target_bdf;

#define ASPEED_MCTP_IOCTL_BASE 0x4d
#define ASPEED_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER \
    _IO(ASPEED_MCTP_IOCTL_BASE, 4)

struct mctp_pcie_hdr
{
    uint8_t fmt_type;
    uint8_t mbz;
    uint16_t mbz_attr_length;
    uint16_t requester; // PCI Requester ID, bdf as physical address
    uint8_t tag;
    uint8_t code;
    uint16_t target;
    uint16_t vendor;
} __attribute__((packed));

static_assert(sizeof(struct mctp_pcie_hdr) == 12);

static struct mctp_pcie_hdr template_hdr = {
    .fmt_type = 0x70, // fmt: 11b,  Set to 10b to indicate a message / 000b :
                      // Route to Root Complex
    .mbz = 0,         // PCIe 1.1/2.0: PCIe reserved bits (4 bits). Set to 0000b
    .mbz_attr_length =
        0x0010,          // Length adn attr, high 10 bits are length, low 6 bits are attr
    .requester = 0x0015, // PCI Requester ID, bdf as physical address
    .tag = 0x00,         // Tag,  pad length, 0x10 for 1 byte
    .code = 0x7f,        // Code, 0x7f for MCTP
    .target = 0x0000,    // notify message
    .vendor = 0xB41A,    // Vendor ID
};

struct mctp_hdr
{
    uint8_t ver;
    uint8_t dest;
    uint8_t src;
    uint8_t flags_seq_tag;
};
static_assert(sizeof(struct mctp_hdr) == 4);

static struct mctp_hdr template_mctp_hdr = {
    .ver = 0x01,           // Version
    .dest = 0x00,          // Destination EID
    .src = 0x00,           // Source EID
    .flags_seq_tag = 0xC8, // EOM/SOM, 0xC8 for EOM and SOM, TO (tag owner)
};

struct mctp_pcie_header
{
    struct mctp_pcie_hdr pcie_hdr;
    struct mctp_hdr mctp_hdr;
} __attribute__((packed));

// bit 7: SOM, bit 6: EOM, bit 3: tag owner
#define MCTP_SOM 0x80
#define MCTP_EOM 0x40
#define MCTP_TO 0x08

static int mctp_init()
{
    int fd = open("/dev/aspeed-mctp", O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr, "Unable to open /dev/mctp device file: %s\n",
                strerror(errno));
        return 1;
    }

    ioctl(fd, ASPEED_MCTP_IOCTL_REGISTER_DEFAULT_HANDLER);

    DEBUG_PRINT("Opened MCTP device, fd: %d\n", fd);
    return fd;
}

static int __wrap_ioctl_tag(int sd, unsigned long req, struct mctp_ioc_tag_ctl *ctl)
{
    return 0;
}

static size_t mctp_pcie_tx_length(size_t len)
{
    // 4 bytes alignment, the div 4 is the padding
    size_t aligned_len = len + (4 - (len % 4)) % 4;
    return aligned_len / 4;
}

#define PCIE_HDR_DATA_LEN_SHIFT 0
#define PCIE_HDR_DATA_LEN_MASK 0xff03

static void pcie_set_data_length(struct mctp_pcie_hdr *hdr, size_t val)
{
    hdr->mbz_attr_length |= ((htobe16(val) & PCIE_HDR_DATA_LEN_MASK) << PCIE_HDR_DATA_LEN_SHIFT);
}

static int mctp_write_one_package(int fd, const void *buf, size_t len, int seq, bool start, bool end)
{
    char request[1024];
    size_t request_len = 0;
    size_t padding = (4 - ((len) % 4)) % 4;
    struct mctp_pcie_header header = {
        .pcie_hdr = template_hdr,
        .mctp_hdr = template_mctp_hdr,
    };
    DEBUG_PRINT("target_bdf: %x\n", target_bdf);

    header.pcie_hdr.fmt_type = 0x72;              // route by id
    header.pcie_hdr.target = target_bdf;          // target bdf
    header.pcie_hdr.tag |= (padding << 4 & 0x30); // pad length
    header.mctp_hdr.flags_seq_tag = 0x08;         // TO (tag owner)
    header.mctp_hdr.src = 0x0;
    header.mctp_hdr.dest = 0x0;

    if (start)
    {
        header.mctp_hdr.flags_seq_tag |= MCTP_SOM;
    }
    if (end)
    {
        header.mctp_hdr.flags_seq_tag |= MCTP_EOM;
    }

    header.mctp_hdr.flags_seq_tag |= (seq << 4 & 0x30);
    DEBUG_PRINT("seq: %d, start: %d, end: %d flags_seq_tag: %x\n", seq, start, end, header.mctp_hdr.flags_seq_tag);

    pcie_set_data_length(&header.pcie_hdr, mctp_pcie_tx_length(len));

    memcpy(request, &header, sizeof(header));
    request_len += sizeof(header);

    // append buf & len
    memcpy(request + request_len, buf, len);

    request_len += len;

    // Add padding to align to 4 bytes

    memset(request + request_len, 0, padding);

    request_len += padding;

    HEXDUMP(request, request_len, "request: ");

    int ret = write(fd, request, request_len);
    if (ret < 0)
    {
        fprintf(stderr, "Failed to write to MCTP device: %s\n",
                strerror(errno));
    }

    return ret;
}

static int mctp_write(int fd, const void *buf, size_t len)
{
    size_t offset = 0;
    int seq = 0;
    while (offset < len)
    {
        size_t remaining = len - offset;
        size_t to_write = remaining > (MTU) ? (MTU) : remaining;
        bool start = offset == 0;
        bool end = offset + to_write == len;
        if (mctp_write_one_package(fd, buf + offset, to_write, seq, start, end) < 0)
        {
            return -1;
        }
        seq += 1;
        offset += to_write;
    }

    return 0;
}

static int mctp_read_one_pacakge(int fd, void *buf, size_t *len)
{
    char response[1024];
    ssize_t bytes_read = read(fd, response, sizeof(response));
    if (bytes_read < 0)
    {
        fprintf(stderr, "Failed to read from MCTP device: %s\n",
                strerror(errno));
        return -1;
    }

    HEXDUMP(response, bytes_read, "response: ");

    memcpy(buf, response, bytes_read);

    *len = bytes_read;

    return 0;
}

#define PCIE_HDR_DATA_LEN_SHIFT 0
#define PCIE_HDR_DATA_LEN_MASK 0xff03

#define PCIE_GET_DATA_LEN(x)                  \
    be16toh(((x >> PCIE_HDR_DATA_LEN_SHIFT) & \
             PCIE_HDR_DATA_LEN_MASK))

static int mctp_poll(int fd, int timeout)
{
    struct pollfd fds = {
        .fd = fd,
        .events = POLLIN,
    };

    int ret = poll(&fds, 1, timeout);
    if (ret < 0)
    {
        fprintf(stderr, "Failed to poll MCTP device: %s\n",
                strerror(errno));
        return ret;
    }

    return ret;
}

static int mctp_read(int fd, void *buf, size_t *len)
{
    *len = 0;
    size_t failed = 0;

    while (1)
    {
        char response[1024];
        ssize_t bytes_read;
        int ret = mctp_read_one_pacakge(fd, response, &bytes_read);

        if (ret < 0)
        {
            fprintf(stderr, "Failed to read from MCTP device: %s\n",
                    strerror(errno));
            failed += 1;
            if (failed > 3)
            {
                return -1;
            }
            continue;
        }

        struct mctp_pcie_header *hdr = (struct mctp_pcie_header *)response;
        if (hdr->pcie_hdr.requester != target_bdf)
        {
            continue;
        }
        size_t payload_len = PCIE_GET_DATA_LEN(hdr->pcie_hdr.mbz_attr_length);

        DEBUG_PRINT("Start of message %x\n", hdr->mctp_hdr.flags_seq_tag);

        if (hdr->mctp_hdr.flags_seq_tag & MCTP_SOM)
        {

            memcpy(buf + *len, response + sizeof(*hdr) + 1, payload_len * 4 - 1);

            *len += (payload_len * 4) - 1;
        }
        else
        {

            memcpy(buf + *len, response + sizeof(*hdr), payload_len * 4);

            *len += payload_len * 4;
        }

        if (hdr->mctp_hdr.flags_seq_tag & MCTP_EOM)
        {
            DEBUG_PRINT("End of message %x\n", hdr->mctp_hdr.flags_seq_tag);
            break;
        }

    poll:
        if (mctp_poll(fd, 1000) < 0)
        {
            fprintf(stderr, "Failed to poll MCTP device: %s\n",
                    strerror(errno));
            return -1;
        }

        DEBUG_PRINT("Continue reading\n");
    }

    DEBUG_PRINT("Read %ld bytes from MCTP\n", *len);
    HEXDUMP(buf, *len, "Read: ");

    return *len;
}

static ssize_t __wrap_sendmsg(int sd, const struct msghdr *hdr, int flags)
{
    // get total length
    size_t iov_len = hdr->msg_iovlen;
    size_t len = 0;

    static char buf[1024 * 1024 * 3];
    buf[0] = 0x84;
    len = 1;

    for (size_t i = 0; i < iov_len; i++)
    {

        memcpy(buf + len, hdr->msg_iov[i].iov_base, hdr->msg_iov[i].iov_len);

        len += hdr->msg_iov[i].iov_len;
    }
    DEBUG_PRINT("__wrap_sendmsg message to MCTP, length: %ld\n", len);

    return mctp_write(sd, buf, len);
}

static ssize_t __wrap_recvmsg(int sd, struct msghdr *hdr, int flags)
{
    DEBUG_PRINT("Receiving message from MCTP\n");
    return mctp_read(sd, hdr->msg_iov->iov_base, &hdr->msg_iov->iov_len);
}

static int __wrap_socket(int family, int type, int protocol)
{
    DEBUG_PRINT("Opening MCTP socket\n");
    return mctp_init();
}

static struct __mi_mctp_socket_ops ops = {
    __wrap_socket,
    __wrap_sendmsg,
    __wrap_recvmsg,
    poll,
    __wrap_ioctl_tag,
};

void setup_pcie_mctp(uint16_t bdf)
{
    target_bdf = bdf;

    __nvme_mi_mctp_set_ops(&ops);
}