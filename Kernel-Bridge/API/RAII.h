#pragma once

template <typename T>
using ObjectDestructor = void (*)(T);

template <typename T>
class Object final {
private:
    T _Object;
    ObjectDestructor<T> _Destructor;
public:
    Object(const Object&) = delete;
    Object(Object&&) = delete;
    Object& operator = (const Object&) = delete;
    Object& operator = (Object&&) = delete;

    Object(T ObjectPtr, ObjectDestructor<T> Destructor) 
    : _Object(ObjectPtr), _Destructor(Destructor) {}
    ~Object() {
        if (_Destructor) _Destructor(_Object);
    }
    T Get() const { return _Object; }
};