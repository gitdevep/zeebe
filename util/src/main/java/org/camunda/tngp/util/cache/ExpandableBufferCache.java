package org.camunda.tngp.util.cache;

import java.nio.ByteBuffer;
import java.util.function.LongFunction;

import org.agrona.DirectBuffer;
import org.agrona.ExpandableDirectByteBuffer;
import org.agrona.MutableDirectBuffer;
import org.agrona.collections.LongLruCache;
import org.agrona.concurrent.UnsafeBuffer;

/**
 * LRU-cache for buffers. The buffers can have a different size. If the buffer
 * size is greater than the given initial size then the underlying buffer is
 * expanded.
 *
 * <p>
 * Inspired by agrona's {@link LongLruCache}.
 */
public class ExpandableBufferCache
{
    private final DirectBuffer readBuffer = new UnsafeBuffer(0, 0);

    private final long keys[];
    private final MutableDirectBuffer[] values;

    private final LongFunction<DirectBuffer> lookup;

    private final int capacity;
    private int size;

    /**
     * Create a new cache.
     *
     * @param cacheCapacity
     *            capacity of the cache
     * @param initialBufferCapacity
     *            initial capacity of the underlying expandable buffers
     * @param lookup
     *            a function for lookup an absent value
     */
    public ExpandableBufferCache(int cacheCapacity, int initialBufferCapacity, LongFunction<DirectBuffer> lookup)
    {
        this.capacity = cacheCapacity;
        this.lookup = lookup;

        size = 0;
        keys = new long[cacheCapacity];

        values = new MutableDirectBuffer[cacheCapacity + 1];
        for (int i = 0; i < values.length; i++)
        {
            values[i] = new ExpandableDirectByteBuffer(initialBufferCapacity);
        }
    }

    public DirectBuffer get(long key)
    {
        final int index = indexOf(key);
        if (index >= 0)
        {
            final MutableDirectBuffer value = values[index];

            makeMostRecent(key, value, index);

            final ByteBuffer byteBuffer = value.byteBuffer();
            // wrap the buffer to the original size
            readBuffer.wrap(byteBuffer, 0, byteBuffer.limit());

            return readBuffer;
        }
        else
        {
            final DirectBuffer buffer = lookup.apply(key);
            if (buffer != null)
            {
                insert(key, buffer);
            }
            return buffer;
        }
    }

    private int indexOf(long key)
    {
        for (int i = 0; i < size; i++)
        {
            if (keys[i] == key)
            {
                return i;
            }
        }
        return -1;
    }

    private void insert(long key, final DirectBuffer buffer)
    {
        final MutableDirectBuffer value = values[size];
        if (size == capacity)
        {
            // drop the least recently used
            recycle(value);
        }
        else
        {
            size += 1;
        }

        copyBuffer(buffer, value);

        makeMostRecent(key, value, size - 1);
    }

    private void copyBuffer(final DirectBuffer source, final MutableDirectBuffer target)
    {
        final ByteBuffer byteBuffer = target.byteBuffer();

        source.getBytes(0, byteBuffer, source.capacity());
        // use the limit to indicate the buffer length
        byteBuffer.limit(source.capacity());
    }

    private void makeMostRecent(long key, MutableDirectBuffer value, int fromIndex)
    {
        // shift cache entries to right (tail)
        for (int i = fromIndex; i > 0; i--)
        {
            keys[i] = keys[i - 1];
            values[i] = values[i - 1];
        }

        keys[0] = key;
        values[0] = value;
    }

    private void recycle(MutableDirectBuffer buffer)
    {
        buffer.setMemory(0, buffer.capacity(), (byte) 0);
        buffer.byteBuffer().clear();
    }

    public void put(long key, DirectBuffer buffer)
    {
        final int index = indexOf(key);
        if (index >= 0)
        {
            final MutableDirectBuffer value = values[index];

            recycle(value);
            copyBuffer(buffer, value);

            makeMostRecent(key, value, index);
        }
        else
        {
            insert(key, buffer);
        }
    }

    public void remove(long key)
    {
        final int index = indexOf(key);
        if (index >= 0)
        {
            recycle(values[index]);

            size -= 1;

            // shift cache entries to left (head)
            for (int i = index; i < size; i++)
            {
                keys[i] = keys[i + 1];
                values[i] = values[i + 1];
            }
        }
    }

    public int getSize()
    {
        return size;
    }

    public void clear()
    {
        for (int i = 0; i < size; i++)
        {
            recycle(values[i]);
        }

        size = 0;
    }
}
