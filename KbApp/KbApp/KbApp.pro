QT += core gui widgets

TARGET = KbApp
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

CONFIG += c++17

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
