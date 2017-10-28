all: net_filter

net_filter: net_filter.c
		gcc -o net_filter net_filter.c -lnetfilter_queue

clean:
		rm net_filter
