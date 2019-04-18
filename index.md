## XDP
Express Data Path is a programmable fast packet processor in the kernel. Details about XDP can be found [here](https://dl.acm.org/citation.cfm?id=3281443), and [here](https://developers.redhat.com/blog/2018/12/06/achieving-high-performance-low-latency-networking-with-xdp-part-1/). This article contains the steps to setup a development environment for XDP.

## Required for this article
### [XDP Setup](https://priyankaselvan.github.io/eXpress-Data-Path--Setup/)

## Other Articles
### [Using XDP Tail Calls]()
### [Modifying packets using XDP]()

## BPF maps
BPF maps are key value stores that can be accessed by both the kernel XDP program and the user program. This is the only method of communication between the kernel XDP program and user space. This article contains instructions to create and access BPF maps from both the kernel XDP program and the user space. 

## XDP Application
To illustrate the use of XDP maps, this article describes an XDP program that counts the number of UDP packets it receives and writes it to a BPF map field. A program in user space reads this value and displays it. 

## Kernel program
The kernel program contains
- Definition of the BPF map
- Reading packet data
- Updated BPF map field

The entire kernel code can be found [here](https://github.com/PriyankaSelvan/xdp-map-udp/blob/master/kernel/udp_kern.c). 
The Makefile for the kernel code can be found [here](https://github.com/PriyankaSelvan/xdp-map-udp/blob/master/kernel/Makefile).

The Makefile just makes sure required header files are accessible. The Makefile compiles the kernel code write using _clang_. This is due to the fact that only _clang_ provides an option of specifying a _bpf_ target required for XDP. 

#### Preprocessors
```
#define KBUILD_MODNAME "foo"
#define asm_volatile_goto(x...)
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"
```
The first two _#define_ are to be defined and are workarounds for clang not being able to work with _asm_goto_ constructs. __These two definitions must be done in all XDP kernel programs__. The rest of the _include_ statements are the ones required for this application. 

#### Function definitions
```
static __always_inline
int parse_ipv4(void *data, u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;

	if(iph+1 > data_end)
		return 0;
	return iph->protocol;
}
```
Functions can be defined in XDP programs as above. Earlier, only inline functions were allowed - hence the `static __always_inline`, but currently, this is not required. XDP can work with regular functions. This function is designed to parse the packet and return the protocol number of the packet. The _if_ condition is the check that makes sure that the geader does not exceed the packet end. These checks are required to pass the BPF verifier before loading the program to the interface. 

#### Map definition
```
struct bpf_map_def SEC("maps") dpcnt = {
                .type = BPF_MAP_TYPE_PERCPU_ARRAY,
                .key_size = sizeof(u32),
                .value_size = sizeof(long),
                .max_entries = 256,
};
```
This is the syntax to follow in order to define a BPF map in an XDP program. The _key_size_, _value_size_, and the _max_entries_ fields are self-explanatory. The _type_ field specifies the type of the map. There are multiple types available for use. Here, the `BPF_MAP_TYPE_PERCPU_ARRAY` type maintains a separate map for each CPU. This is faster since maintaining a central map will spend time in acquiring and releasing locks in order for the CPUs to modify them. In the user program, we will read the values stored by all the CPUs and add them up for our final packet count. 

#### Updating map field
```
if(ipproto == IPPROTO_UDP){
		value = bpf_map_lookup_elem(&dpcnt, &ipproto);
		if(value)
			*value += 1;
		return XDP_DROP;
	}
```
This part of the code updates the UDP packet count in the map. _if_ the protocol is UDP then we lookup for the key _ipproto_ using `bpf_map_lookup_elem`. Therefore, the number of UDP packets is stored at key equal to the protocol number of UDP. Lookup returns a pointer to the value and the value can be updated. This code eventually drops all the UDP packets with `return XDP_DROP;`. 

We can now build the kernel program using `make`. 

## User program
The user program contains the following
- Finds the kernel object file
- Loads the kernel object file to an interface
- Waits for some traffic to be sent to the interface
- Looks up map field values for all CPUs
- Adds the values to get total count
- Displays the total number of UDP packets

The entire user program can be found [here](https://github.com/PriyankaSelvan/xdp-map-udp/blob/master/user/udp_usr.c).
The Makefile to compile the user program can be found [here](https://github.com/PriyankaSelvan/xdp-map-udp/blob/master/user/Makefile). 

The Makefile just makes sure that the header files are accessible and uses _gcc_ to compile the user program. 

#### Finding kernel object file
```
struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = "../kernel/udp_kern.o",
	};

	if(bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
	{
		printf("\nCould not load program");
		return 1;
	}
```
