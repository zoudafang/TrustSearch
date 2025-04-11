#include <atomic>
#include <iostream>

class AtomicArray
{
private:
    std::atomic<uint32_t> *array;
    size_t capacity = 0;

public:
    AtomicArray(size_t initial_size) : capacity(initial_size)
    {
        array = new std::atomic<uint32_t>[capacity];
        for (size_t i = 0; i < capacity; ++i)
        {
            array[i].store(0);
        }
    }
    AtomicArray(const AtomicArray &other) : capacity(other.capacity), array(new std::atomic<uint32_t>[capacity])
    {
        for (size_t i = 0; i < capacity; ++i)
        {
            array[i].store(other.array[i].load());
        }
    }

    AtomicArray(AtomicArray &&other) noexcept : capacity(other.capacity), array(other.array)
    {
        other.array = nullptr;
        other.capacity = 0;
    }

    AtomicArray &operator=(const AtomicArray &other)
    {
        if (this != &other)
        {
            AtomicArray temp(other);
            std::swap(array, temp.array);
            std::swap(capacity, temp.capacity);
        }
        return *this;
    }

    AtomicArray() : capacity(1)
    {
        array = new std::atomic<uint32_t>[1];
    }

    ~AtomicArray()
    {
        delete[] array;
    }

    void resize(size_t new_size)
    {
        if (new_size > capacity)
        {
            std::atomic<uint32_t> *new_array = new std::atomic<uint32_t>[new_size];
            for (size_t i = 0; i < capacity; ++i)
            {
                new_array[i].store(array[i].load());
            }
            for (size_t i = capacity; i < new_size; ++i)
            {
                new_array[i].store(0);
            }
            if (capacity)
            {
                delete[] array;
            }
            array = new_array;
            capacity = new_size;
        }
    }

    void clear()
    {
        for (size_t i = 0; i < capacity; ++i)
        {
            array[i].store(0);
        }
    }
    int size()
    {
        return capacity;
    }
    std::atomic<uint32_t> &operator[](size_t index)
    {
        return array[index];
    }
};