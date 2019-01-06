QT += core gui widgets

TARGET = Kernel-Toolkit
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

CONFIG += c++17 static static-runtime
QMAKE_LFLAGS_RELEASE += -static -static-runtime

INCLUDEPATH += \
    ../../SharedTypes \
    ../../User-Bridge/API/ \
    ../../User-Bridge/API/PEUtils/

LIBS += \
    -lAdvapi32

SOURCES += \
    ObjectsStorage.cpp \
    MainWindow.cpp \
    Main.cpp \
    ../../User-Bridge/API/PEUtils/PEAnalyzer.cpp \
    ../../User-Bridge/API/PEUtils/PELoader.cpp \
    ../../User-Bridge/API/CommPort.cpp \
    ../../User-Bridge/API/DriversUtils.cpp \
    ../../User-Bridge/API/Rtl-Bridge.cpp \
    ../../User-Bridge/API/User-Bridge.cpp

HEADERS += \
    ObjectsStorage.h \
    MainWindow.h \
    ../../SharedTypes/CtlTypes.h \
    ../../SharedTypes/FltTypes.h \
    ../../SharedTypes/WdkTypes.h \
    ../../User-Bridge/API/PEUtils/PEAnalyzer.h \
    ../../User-Bridge/API/PEUtils/PELoader.h \
    ../../User-Bridge/API/CommPort.h \
    ../../User-Bridge/API/DriversUtils.h \
    ../../User-Bridge/API/Flt-Bridge.h \
    ../../User-Bridge/API/Rtl-Bridge.h \
    ../../User-Bridge/API/User-Bridge.h

FORMS += \
    MainWindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

DISTFILES +=

RESOURCES +=
