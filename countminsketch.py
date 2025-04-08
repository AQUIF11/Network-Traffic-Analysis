# countminsketch.py

import hashlib
import random

class CountMinSketch:
    def __init__(self, width, depth, seed=42):
        self.width = width
        self.depth = depth
        self.tables = [[0] * width for _ in range(depth)]
        random.seed(seed)
        self.seeds = [random.randint(0, 2**31 - 1) for _ in range(depth)]

    def _hash(self, item, seed):
        h = hashlib.md5(item + seed.to_bytes(4, byteorder='little'))
        return int(h.hexdigest(), 16) % self.width

    def update(self, item, count=1):
        if isinstance(item, str):
            item = item.encode('utf-8')
        for d in range(self.depth):
            idx = self._hash(item, self.seeds[d])
            self.tables[d][idx] += count

    def estimate(self, item):
        if isinstance(item, str):
            item = item.encode('utf-8')
        min_count = float('inf')
        for d in range(self.depth):
            idx = self._hash(item, self.seeds[d])
            min_count = min(min_count, self.tables[d][idx])
        return min_count
