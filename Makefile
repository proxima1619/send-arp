all:
	g++ -std=c++11 -Wall -Wextra -O2 -c arphdr.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -c ethhdr.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -c ip.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -c mac.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -c send-arp.cpp
	g++ -std=c++11 -Wall -Wextra -O2 -o send-arp arphdr.o ethhdr.o ip.o mac.o send-arp.o -lpcap

clean:
	rm -f *.o send-arp
