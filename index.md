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
To illustrate the use of XDP maps, this article describes an XDP program that counts the number of UDP packets it receives and writes it to a BPF map field. A program in user space reads this value and displays it. The entire application can be found in [this](https://github.com/PriyankaSelvan/xdp-map-udp) repository.  

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
struct bpf_object *obj;
int prog_fd;
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
First, the kernel object file is found and loaded to an object of type `bof_object`. The `bpf_prog_load_xattr` function also gets the file descriptor of the kernel program into `prog_fd`. 

#### Loading the kernel program to an interface
```
static __u32 xdp_flags = XDP_FLAGS_DRV_MODE;
int ifindex = if_nametoindex(argv[1]);
if(bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
                printf("\nlink set xdp fd failed");
                return 1;
        }
```
The XDP program is loaded to an interface taken as a command line argument. `xdp_flags` is set to `XDP_FLAGS_DRV_MODE` where the packets are read by the XDP program before SKB allocation. To be able to read packets after SKB allocation, `xdp_flags` can be set to `XDP_FLAGS_SKB_MODE`. 

#### Read from map
```
struct bpf_map *map = bpf_object__find_map_by_name(obj, "dpcnt");
        
unsigned int nr_cpus = bpf_num_possible_cpus();
__u64 values[nr_cpus];
__u32 key = 17; // protocol number for UDP
__u64 sum = 0;
int cpu;

if(!map){
	printf("\nFinding a map obj file failed");
	return 1;
}

map_fd = bpf_map__fd(map);

if(bpf_map_lookup_elem(map_fd, &key, &values)){
	printf("\nLookup failed");
	return 1;
}
	
for(cpu = 0; cpu < nr_cpus; cpu++)
	sum += values[cpu];
```
Here, the required map is found, its file descriptor is obtained and the required field is looked up. Since, the protocol number of UDP was used as the key, here, the key 17 is used. In the kernel program, the map was of type `BPF_MAP_TYPE_PERCPU_ARRAY`. Therefore, here all the values stored by all the CPUs must be looked up and added up to get the global result. 

### Writing to a map from the user and reading from the kernel
In a situation where a field has to be written from the userspace and has to be read from the kernel, the procedure is exactly the same. The only thing to keep in mind in this case is that, the user program must be alive when the kernel reads from the map. Otherwise, the kernel program cannot find the entry made by the user program. 

This concludes the information required to use BPF maps from XDP programs. Other articles in the same topic are listed below. 


### [XDP Setup](https://priyankaselvan.github.io/eXpress-Data-Path--Setup/)
### [Using XDP Tail Calls]()
### [Modifying packets using XDP]()

