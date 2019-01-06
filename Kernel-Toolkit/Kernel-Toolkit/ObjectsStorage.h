#ifndef OBJECTSSTORAGE_H
#define OBJECTSSTORAGE_H

#include <Windows.h>

#include <WdkTypes.h>
#include <CtlTypes.h>
#include <User-Bridge.h>

#include <list>

class ObjectsStorage {
private:
    std::list<WdkTypes::PVOID> ReferencedObjects;
    std::list<WdkTypes::HANDLE> Handles;
    std::list<WdkTypes::PVOID> AllocatedMemory;
    std::list<Mdl::MAPPING_INFO> Mappings;
public:
    ObjectsStorage();
    ~ObjectsStorage();
    void AddReferencedObject(WdkTypes::PVOID Object);
    void AddHandle(WdkTypes::HANDLE Handle);
    void AddAllocatedMemory(WdkTypes::PVOID BaseAddress);
    void AddMapping(const Mdl::MAPPING_INFO& Mapping);
};

#endif // OBJECTSSTORAGE_H
