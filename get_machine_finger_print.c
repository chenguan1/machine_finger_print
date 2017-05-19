#define WIN64

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "se_unistd.h"
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined(WIN32) || defined(WIN64)
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <stdio.h>
#include <windows.h>
#include <setupapi.h>
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"setupapi.lib")
#else
#include <sys/ioctl.h>
#include <linux/hdreg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#endif
#include <sys/types.h>
#include "get_machine_finger_print.h"

static char *machine_finger_print = NULL;
static char *msg_curr = NULL;

#if defined(UNIX32) || defined(UNIX64)

/* Use memory alignment workaround or not */
#ifdef __ia64__
#define ALIGNMENT_WORKAROUND
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef signed short i16;
typedef unsigned int u32;

/*
 * You may use the following defines to adjust the type definitions
 * depending on the architecture:
 * - Define BIGENDIAN on big-endian systems. Untested, as all target
 *   systems to date are little-endian.
 * - Define ALIGNMENT_WORKAROUND if your system doesn't support
 *   non-aligned memory access. In this case, we use a slower, but safer,
 *   memory access method. This should be done automatically in config.h
 *   for architectures which need it.
 */

#ifdef BIGENDIAN
typedef struct {
	u32 h;
	u32 l;
} u64;
#else
typedef struct {
	u32 l;
	u32 h;
} u64;
#endif

#ifdef ALIGNMENT_WORKAROUND
static inline u64 U64(u32 low, u32 high)
{
	u64 self;

	self.l = low;
	self.h = high;

	return self;
}
#endif

#ifdef ALIGNMENT_WORKAROUND
#	ifdef BIGENDIAN
#	define WORD(x) (u16)((x)[1] + ((x)[0] << 8))
#	define DWORD(x) (u32)((x)[3] + ((x)[2] << 8) + ((x)[1] << 16) + ((x)[0] << 24))
#	define QWORD(x) (U64(DWORD(x + 4), DWORD(x)))
#	else /* BIGENDIAN */
#	define WORD(x) (u16)((x)[0] + ((x)[1] << 8))
#	define DWORD(x) (u32)((x)[0] + ((x)[1] << 8) + ((x)[2] << 16) + ((x)[3] << 24))
#	define QWORD(x) (U64(DWORD(x), DWORD(x + 4)))
#	endif /* BIGENDIAN */
#else /* ALIGNMENT_WORKAROUND */
#define WORD(x) (u16)(*(const u16 *)(x))
#define DWORD(x) (u32)(*(const u32 *)(x))
#define QWORD(x) (*(const u64 *)(x))
#endif /* ALIGNMENT_WORKAROUND */

#include <sys/mman.h>
#ifndef MAP_FAILED
#define MAP_FAILED ((void *) -1)
#endif /* !MAP_FAILED */

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
void *mem_chunk(size_t base, size_t len, const char *devmem)
{
	void *p;
	int fd;
	size_t mmoffset;
	void *mmp;

	if ((fd = open(devmem, O_RDONLY)) == -1)
	{
		perror(devmem);
		return NULL;
	}

	if ((p = malloc(len)) == NULL)
	{
		perror("malloc");
		return NULL;
	}

#ifdef _SC_PAGESIZE
	mmoffset = base % sysconf(_SC_PAGESIZE);
#else
	mmoffset = base % getpagesize();
#endif /* _SC_PAGESIZE */
	/*
	 * Please note that we don't use mmap() for performance reasons here,
	 * but to workaround problems many people encountered when trying
	 * to read from /dev/mem using regular read() calls.
	 */
	mmp = mmap(0, mmoffset + len, PROT_READ, MAP_SHARED, fd, base - mmoffset);
	if (mmp == MAP_FAILED) {
		printf("failed to mmap\n");
		exit(1);
	}

	memcpy(p, (u8 *)mmp + mmoffset, len);

	if (munmap(mmp, mmoffset + len) == -1)
	{
		fprintf(stderr, "%s: ", devmem);
		perror("munmap");
	}

	if (close(fd) == -1)
		perror(devmem);

	return p;
}

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

void *mem_chunk(size_t base, size_t len, const char *devmem);

#define LEFT_SIZE (BUF_SIZE + machine_finger_print - msg_curr)
 
static int push_msg(const char *fmt, ...)
{
	int ret;
	if (!fmt)
		return -1;
	va_list args;
	va_start(args, fmt);
    ret = vsnprintf(msg_curr, LEFT_SIZE, fmt, args );
	va_end(args);
	if (ret < 0)
		return -1;
	msg_curr += ret;
	return 0;
}

struct dmi_header
{
	u8 type;
	u8 length;
	u16 handle;
	u8 *data;
};

static const char *bad_index = "<BAD INDEX>";
static const char *dmi_string(const struct dmi_header *dm, u8 s)
{
	char *bp = (char *)dm->data;
	size_t i, len;

	if (s == 0)
		return "Not Specified";

	bp += dm->length;
	while (s > 1 && *bp)
	{
		bp += strlen(bp);
		bp++;
		s--;
	}

	if (!*bp)
		return bad_index;

	{
		/* ASCII filtering */
		len = strlen(bp);
		for (i = 0; i < len; i++)
			if (bp[i] < 32 || bp[i] == 127)
				bp[i] = '.';
	}

	return bp;
}

static void dmi_decode(const struct dmi_header *h, u16 ver)
{
	const u8 *data = h->data;
	ver += ver;

	/*
	 * Note: DMI types 37, 39 and 40 are untested
	 */
	switch (h->type)
	{
		case 0: /* 7.1 BIOS Information */
			push_msg("BIOS Information\n");
			if (h->length < 0x12) break;
			push_msg("\tVersion: %s\n", dmi_string(h, data[0x05]));
			/*
			 * On IA-64, the BIOS base address will read 0 because
			 * there is no BIOS. Skip the base address and the
			 * runtime size in this case.
			 */
			break;

		case 1: /* 7.2 System Information */
			push_msg("System Information\n");
			if (h->length < 0x08) break;
			push_msg("\tSerial Number: %s\n",
				dmi_string(h, data[0x07]));
			break;

		case 2: /* 7.3 Base Board Information */
			push_msg("Base Board Information\n");
			if (h->length < 0x08) break;
			push_msg("\tSerial Number: %s\n",
				dmi_string(h, data[0x07]));
			break;

		case 4: /* 7.5 Processor Information */
			push_msg("Processor Information\n");
			if (h->length < 0x1A) break;
			push_msg("\tID: %02X %02X %02X %02X %02X %02X %02X %02X\n",
				data[0x08], data[0x09], data[0x0a], data[0x0b], data[0x0c], data[0x0d], data[0x0e], data[0x0f]);
			push_msg("\tVersion: %s\n",
				dmi_string(h, data[0x10]));
			break;

		case 17: /* 7.18 Memory Device */
			push_msg("Memory Device\n");
			if (h->length < 0x15) break;
			push_msg("\tSerial Number: %s\n",
				dmi_string(h, data[0x18]));
			break;
	}
}

static void to_dmi_header(struct dmi_header *h, u8 *data)
{
	h->type = data[0];
	h->length = data[1];
	h->handle = WORD(data + 2);
	h->data = data;
}

static void dmi_table(u32 base, u16 len, u16 num, u16 ver, const char *devmem)
{
	u8 *buf;
	u8 *data;
	int i = 0;

	if ((buf = mem_chunk(base, len, devmem)) == NULL)
	{
		fprintf(stderr, "Table is unreachable, sorry."
			"\n");
		return;
	}

	data = buf;
	while (i < num && data+4 <= buf + len) /* 4 is the length of an SMBIOS structure header */
	{
		u8 *next;
		struct dmi_header h;

		to_dmi_header(&h, data);

		/*
		 * If a short entry is found (less than 4 bytes), not only it
		 * is invalid, but we cannot reliably locate the next entry.
		 * Better stop at this point, and let the user know his/her
		 * table is broken.
		 */
		if (h.length < 4)
		{
			printf("Invalid entry length (%u). DMI table is "
			       "broken! Stop.\n\n", (unsigned int)h.length);
			break;
		}

		/* look for the next handle */
		next = data + h.length;
		while (next - buf + 1 < len && (next[0] != 0 || next[1] != 0))
			next++;
		next += 2;
		{
			if (next - buf <= len)
			{
				dmi_decode(&h, ver);
			}
		}

		data = next;
		i++;
	}

	free(buf);
}

static int smbios_decode(u8 *buf, const char *devmem)
{
	u16 ver;

	ver = (buf[0x06] << 8) + buf[0x07];
	/* Some BIOS report weird SMBIOS version, fix that up */
	switch (ver)
	{
		case 0x021F:
		case 0x0221:
			ver = 0x0203;
			break;
		case 0x0233:
			ver = 0x0206;
			break;
	}

    snprintf(msg_curr, LEFT_SIZE, "SMBIOS %u.%u present.\n", ver >> 8, ver & 0xFF);
	dmi_table(DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C),
		ver, devmem);

	return 1;
}

static int getMAC(const char *dev)
{
	struct ifreq ifreq;
    int sock = 0;

    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock < 0) {
        perror("error sock");
        return -1;
    }

    strcpy(ifreq.ifr_name ,dev);
    if(ioctl(sock,SIOCGIFHWADDR,&ifreq) < 0) {
        perror("error ioctl");
        return -1;
    }

	push_msg("%s MAC ", dev);
    int i = 0;
    for(i = 0; i < 5; i++){
        push_msg("%02X:", (unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
    }
	push_msg("%02X\n", (unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
                
    return 0;
}

#define DEFAULT_MEM_DEV "/dev/mem"
static int gen_machine_finger_print(char* pBuffer)
{
	if (machine_finger_print != NULL)
		free(machine_finger_print);
	machine_finger_print = (char *)calloc(1, BUF_SIZE);
	msg_curr = machine_finger_print;
	const char *devmem = DEFAULT_MEM_DEV;
	off_t fp;
	u8 *buf = NULL;
	int found = 0;

	if ((buf = mem_chunk(0xF0000, 0x10000, devmem)) == NULL)
	{
		return -1;
	}

	for (fp = 0; fp <= 0xFFF0; fp += 16)
	{
		if (memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0)
		{
			if (smbios_decode(buf+fp, devmem))
			{
				found++;
				fp += 16;
			}
		}
	}

	free(buf);
	if (!found)
		return -1;

	getMAC("eth0");
    strcpy(pBuffer, machine_finger_print);
	return 0;
}

#endif

#if defined (WIN32) || defined (WIN64)

/*
const char* getMAC()
{
	PIP_ADAPTER_INFO pIpAdapterInfo = (PIP_ADAPTER_INFO)malloc(sizeof(IP_ADAPTER_INFO));
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
	int netCardNum = 0;
	int IPnumPerNetCard = 0;
	char* str = (char*)calloc(1,1024);

	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		free(pIpAdapterInfo);
		pIpAdapterInfo = (PIP_ADAPTER_INFO)malloc(stSize);
		nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
	}
	if (ERROR_SUCCESS == nRel)
	{
		sprintf_(str,"IpAdpter Name: %s\nIpAdapter Description：%s",
			pIpAdapterInfo->AdapterName,pIpAdapterInfo->Description);
	}
	if (pIpAdapterInfo)
	{
		free(pIpAdapterInfo);
	}
	return str;
}
*/

GUID pGUID= { 0x4D36E968 , 0xE325 , 0x11CE , 0xBF , 0xC1 , 0x08 , 0x00 , 0x2B , 0xE1 , 0x03 , 0x18};

void GetDisplayInfo(char* catString)
{
	HDEVINFO hDevInfo = 0;
	SP_DEVINFO_DATA spDevinofData = {0};

	char szClass[128]={0};
	char szBuf[128]  ={0};
	char info[1024] = {0};
	DWORD dwData=0,i=1;
	BOOL bRtn=FALSE;

	hDevInfo = SetupDiGetClassDevs(&pGUID,0,NULL,DIGCF_PRESENT);

	SetupDiGetClassDescriptionA(&pGUID,szClass,128,&dwData);

	spDevinofData.cbSize = sizeof(SP_DEVINFO_DATA);
	for(i=0;SetupDiEnumDeviceInfo(hDevInfo,i,&spDevinofData);i++)
	{
		bRtn = SetupDiGetDeviceRegistryPropertyA(hDevInfo,&spDevinofData,SPDRP_DEVICEDESC,0L,(PBYTE)szBuf,128,0);
		strcat(info,szBuf);
		strcat(info," ");
	}
	strcat(catString,info);
}

void GetIPapatertionInfo(char* catString)
{
	PIP_ADAPTER_INFO pIpAdapterInfo = (PIP_ADAPTER_INFO)malloc(sizeof(IP_ADAPTER_INFO));
	unsigned long stSize = sizeof(IP_ADAPTER_INFO);
	int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
	char* info = (char*)calloc(1,1024);

	if (ERROR_BUFFER_OVERFLOW == nRel)
	{
		free(pIpAdapterInfo);
		pIpAdapterInfo = (PIP_ADAPTER_INFO)malloc(stSize);
		nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
	}
	if (ERROR_SUCCESS == nRel)
	{
		//strcat(info,pIpAdapterInfo->Description);
		strcat(info,pIpAdapterInfo->AdapterName);
	}
	if (pIpAdapterInfo)
	{
		free(pIpAdapterInfo);
	}
	strcat(catString,info);
	if(info)
		free(info);
}

static int gen_machine_finger_print(char* pBuffer)
{
	char info[1024] = {0};
	GetDisplayInfo(info);
	GetIPapatertionInfo(info);
	//machine_finger_print = (char *)calloc(1, BUF_SIZE);
	strcat(pBuffer,info);
	return 0;
}

#endif

void get_machine_finger_print(char* pBuffer)
{
	if(!pBuffer)
		return;
#if defined(UNIX32) || defined(UNIX64)
	gen_machine_finger_print(pBuffer);
	if (strlen(pBuffer) >= BUF_SIZE) {
		fprintf(stderr, "finger_print is too larger\n");
		exit(1);
	}
#elif defined(WIN32) || defined(WIN64)
	gen_machine_finger_print(pBuffer);
	if (strlen(pBuffer) >= BUF_SIZE) {
		fprintf(stderr, "finger_print is too larger\n");
		exit(1);
	}
#endif
}
