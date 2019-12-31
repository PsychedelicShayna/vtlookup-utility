CONFIG -= app_bundle
QT -= gui

TARGET = vtlookup

CONFIG += c++17 console

# Include paths for OpenSSL and LibCurl
INCLUDEPATH += \
    C:/OpenSSl-Win64/include \
    C:/Curl/include

# LibCurl + dependencies linkage.
LIBS += -LC:/Curl/builds/precompiled/static-release-x64
LIBS += \
    -llibcurl_a \
    -lws2_32 \
    -lwldap32 \
    -ladvapi32 \
    -lkernel32 \
    -lcomdlg32 \
    -lcrypt32 \
    -lnormaliz

# OpenSSL linkage.
LIBS += -LC:/OpenSSL-Win64/lib/
LIBS += \
    -llibcrypto \
    -llibssl \
    -lopenssl

SOURCES += \
    source/main.cxx \
    source/vtlookup.cxx

HEADERS += \
    source/json.hpp \
    source/vtlookup.hxx

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
