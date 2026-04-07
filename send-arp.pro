TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
TARGET = send-arp
LIBS += -lpcap

SOURCES += \
	arphdr.cpp \
	ethhdr.cpp \
	ip.cpp \
	mac.cpp \
	send-arp.cpp

HEADERS += \
	arphdr.h \
	ethhdr.h \
	ip.h \
	mac.h
