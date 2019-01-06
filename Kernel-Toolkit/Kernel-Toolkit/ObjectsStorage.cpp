#include "ObjectsStorage.h"

ObjectsStorage::ObjectsStorage() : ReferencedObjects(), Handles(), AllocatedMemory(), Mappings()
{

}

ObjectsStorage::~ObjectsStorage()
{
    using namespace VirtualMemory;
    using namespace Mdl;
    using namespace Processes::Descriptors;
    for (const auto& Entry : ReferencedObjects) {
        if (Entry) KbDereferenceObject(Entry);
    }
    for (const auto& Entry : Handles) {
        if (Entry) KbCloseHandle(Entry);
    }
    for (const auto& Entry : AllocatedMemory) {
        if (Entry) KbFreeKernelMemory(Entry);
    }
    for (const auto& Entry : Mappings) {
        KbUnmapMemory(const_cast<Mdl::PMAPPING_INFO>(&Entry));
    }
}

void ObjectsStorage::AddReferencedObject(WdkTypes::PVOID Object)
{
    ReferencedObjects.emplace_back(Object);
}

void ObjectsStorage::AddHandle(WdkTypes::HANDLE Handle)
{
    Handles.emplace_back(Handle);
}

void ObjectsStorage::AddAllocatedMemory(WdkTypes::PVOID BaseAddress)
{
    AllocatedMemory.emplace_back(BaseAddress);
}

void ObjectsStorage::AddMapping(const Mdl::MAPPING_INFO& Mapping)
{
    Mappings.emplace_back(Mapping);
}
