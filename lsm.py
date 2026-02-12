import os
import struct
import time
import random
import bisect

class BloomFilter:
    def __init__(self, size=8192, num_hashes=4):
        self.size = size
        self.num_hashes = num_hashes
        self.bits = bytearray((size + 7) // 8)
    
    def _hash(self, key, seed):
        h = hash(key + str(seed))
        return h % self.size
    
    def add(self, key):
        for i in range(self.num_hashes):
            pos = self._hash(key, i)
            self.bits[pos // 8] |= (1 << (pos % 8))
    
    def might_contain(self, key):
        for i in range(self.num_hashes):
            pos = self._hash(key, i)
            if not (self.bits[pos // 8] & (1 << (pos % 8))):
                return False
        return True
    
    def serialize(self):
        return struct.pack('II', self.size, self.num_hashes) + self.bits
    
    @classmethod
    def deserialize(cls, data):
        size, num_hashes = struct.unpack('II', data[:8])
        bits = data[8:]
        bf = cls()
        bf.size = size
        bf.num_hashes = num_hashes
        bf.bits = bytearray(bits)
        return bf

class SSTable:
    def __init__(self, filename, data=None):
        self.filename = filename
        self.index = []
        self.bloom = None
        
        if data is not None:
            self._build(data)
        else:
            self._load()
    
    def _build(self, data):
        data_sorted = sorted(data, key=lambda x: x[0])
        self.bloom = BloomFilter()
        
        offsets = []
        with open(self.filename, 'wb') as f:
            for key, value in data_sorted:
                self.bloom.add(key)
                key_b = key.encode()
                value_b = value.encode()
                record = struct.pack('I', len(key_b)) + key_b + struct.pack('I', len(value_b)) + value_b
                offsets.append(f.tell())
                f.write(record)
        
        self.index = []
        with open(self.filename, 'rb') as f:
            for (key, _), offset in zip(data_sorted, offsets):
                self.index.append((key, offset))
        
        with open(self.filename, 'ab') as f:
            index_data = struct.pack('I', len(self.index))
            for key, offset in self.index:
                key_b = key.encode()
                index_data += struct.pack('I', len(key_b)) + key_b + struct.pack('Q', offset)
            f.write(index_data)
            f.write(struct.pack('I', len(index_data)))
            f.write(self.bloom.serialize())
    
    def _load(self):
        if not os.path.exists(self.filename):
            return
        
        with open(self.filename, 'rb') as f:
            f.seek(-4, os.SEEK_END)
            index_size = struct.unpack('I', f.read(4))[0]
            f.seek(-4 - index_size, os.SEEK_END)
            count = struct.unpack('I', f.read(4))[0]
            for _ in range(count):
                key_len = struct.unpack('I', f.read(4))[0]
                key = f.read(key_len).decode()
                offset = struct.unpack('Q', f.read(8))[0]
                self.index.append((key, offset))
            bloom_data = f.read()
            if len(bloom_data) >= 8:
                self.bloom = BloomFilter.deserialize(bloom_data)
    
    def get(self, key):
        if self.bloom is None or not self.bloom.might_contain(key):
            return None
        
        keys = [k for k, _ in self.index]
        pos = bisect.bisect_left(keys, key)
        if pos >= len(keys) or keys[pos] != key:
            return None
        
        offset = self.index[pos][1]
        with open(self.filename, 'rb') as f:
            f.seek(offset)
            key_len = struct.unpack('I', f.read(4))[0]
            f.seek(key_len, os.SEEK_CUR)
            value_len = struct.unpack('I', f.read(4))[0]
            value = f.read(value_len).decode()
            return value
    
    def range(self, start, end):
        keys = [k for k, _ in self.index]
        left = bisect.bisect_left(keys, start)
        right = bisect.bisect_right(keys, end)
        
        result = []
        for i in range(left, right):
            key = keys[i]
            value = self.get(key)
            if value is not None:
                result.append((key, value))
        return result
    
    def size_bytes(self):
        return os.path.getsize(self.filename) if os.path.exists(self.filename) else 0
    
    def cleanup(self):
        if os.path.exists(self.filename):
            os.remove(self.filename)

class LSMTree:
    def __init__(self, memtable_limit=100):
        self.memtable = {}
        self.memtable_limit = memtable_limit
        self.levels = []
    
    def put(self, key, value):
        self.memtable[key] = value
        if len(self.memtable) >= self.memtable_limit:
            self._flush_memtable()
    
    def _flush_memtable(self):
        if not self.memtable:
            return
        
        if not self.levels:
            self.levels.append([])
        
        filename = f"l0_{len(self.levels[0])}.sst"
        sst = SSTable(filename, list(self.memtable.items()))
        self.levels[0].append(sst)
        self.memtable.clear()
        
        if len(self.levels[0]) > 2:
            self._compact_level(0)
    
    def _compact_level(self, level):
        if level >= len(self.levels) or not self.levels[level]:
            return
        
        merged = {}
        for sst in self.levels[level]:
            for k, v in sst.range("", "~"):
                merged[k] = v
        
        if level + 1 < len(self.levels):
            for sst in self.levels[level + 1]:
                for k, v in sst.range("", "~"):
                    merged[k] = v
        
        if level + 1 >= len(self.levels):
            self.levels.append([])
        
        next_level = self.levels[level + 1]
        for sst in next_level:
            sst.cleanup()
        next_level.clear()
        
        filename = f"l{level+1}_0.sst"
        sst = SSTable(filename, list(merged.items()))
        next_level.append(sst)
        
        for sst in self.levels[level]:
            sst.cleanup()
        self.levels[level].clear()
    
    def get(self, key):
        if key in self.memtable:
            return self.memtable[key]
        
        for i in range(len(self.levels) - 1, -1, -1):
            for sst in self.levels[i]:
                val = sst.get(key)
                if val is not None:
                    return val
        return None
    
    def range(self, start, end):
        result = {}
        for k, v in self.memtable.items():
            if start <= k <= end:
                result[k] = v
        
        for i in range(len(self.levels) - 1, -1, -1):
            for sst in self.levels[i]:
                for k, v in sst.range(start, end):
                    result[k] = v
        
        return sorted(result.items())

def test_correctness():
    tree = LSMTree(memtable_limit=10)
    tree.put("apple", "red")
    tree.put("banana", "yellow")
    tree.put("cherry", "red")
    
    assert tree.get("apple") == "red"
    assert tree.get("banana") == "yellow"
    assert tree.get("cherry") == "red"
    assert tree.get("grape") is None
    
    range_test = tree.range("b", "d")
    assert len(range_test) == 2
    assert range_test[0][0] == "banana"
    assert range_test[1][0] == "cherry"
    
    tree.put("banana", "green")
    assert tree.get("banana") == "green"
    
    for level in tree.levels:
        for sst in level:
            sst.cleanup()
    for f in os.listdir('.'):
        if f.endswith('.sst'):
            try:
                os.remove(f)
            except:
                pass
    
    print("✓ Correctness tests passed")

def benchmark():
    tree = LSMTree(memtable_limit=100)
    
    def rand_str(length):
        return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(length))
    
    start = time.time()
    for i in range(500):
        tree.put(rand_str(10), rand_str(20))
    insert_time = (time.time() - start) * 1000
    
    level_count = len(tree.levels)
    level_sizes = [len(l) for l in tree.levels]
    total_keys = len(tree.range("a", "z"))
    
    start = time.time()
    for i in range(100):
        tree.get(rand_str(10))
    get_time = (time.time() - start) * 1000
    
    start = time.time()
    for i in range(20):
        tree.range("k", "m")
    range_time = (time.time() - start) * 1000
    
    print(f"Insert 500 keys: {insert_time:.1f} ms")
    print(f"Get 100 keys: {get_time:.1f} ms")
    print(f"Range 20 times: {range_time:.1f} ms")
    print(f"Levels created: {level_count} (files per level: {level_sizes})")
    print(f"Total keys stored: {total_keys}")
    
    for level in tree.levels:
        for sst in level:
            sst.cleanup()
    for f in os.listdir('.'):
        if f.endswith('.sst'):
            try:
                os.remove(f)
            except:
                pass

if __name__ == "__main__":
    test_correctness()
    benchmark()
    print("Done.")