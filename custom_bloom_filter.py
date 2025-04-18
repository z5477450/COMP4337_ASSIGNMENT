import math
from bloom_filter.bloom_filter import (
    Array_backend,
    File_seek_backend,
    Mmap_backend,
    Array_then_file_seek_backend,
    try_unlink,
    get_filter_bitno_probes
)

class BloomFilter(object):
    """Probabilistic set membership testing for large sets"""
    def __init__(self,
                 max_elements=10000,
                 error_rate=0.1,
                 probe_bitnoer=get_filter_bitno_probes,
                 filename=None,
                 start_fresh=False,
                 size_bits: int = None,
                 num_hashes: int = None):
        # pylint: disable=R0913
        # R0913: We want a few arguments
        if max_elements <= 0:
            raise ValueError('ideal_num_elements_n must be > 0')
        if not (0 < error_rate < 1):
            raise ValueError('error_rate_p must be between 0 and 1 exclusive')

        self.error_rate_p = error_rate
        # With fewer elements, we should do very well.  With more elements, our error rate "guarantee"
        # drops rapidly.
        self.ideal_num_elements_n = max_elements
        if size_bits is not None:
            self.num_bits_m = size_bits
        else:
            numerator = -1 * self.ideal_num_elements_n * math.log(self.error_rate_p)
            denominator = math.log(2) ** 2
            real_num_bits_m = numerator / denominator
            self.num_bits_m = int(math.ceil(real_num_bits_m))

        if filename is None:
            self.backend = Array_backend(self.num_bits_m)
        elif isinstance(filename, tuple) and isinstance(filename[1], int):
            if start_fresh:
                try_unlink(filename[0])
            if filename[1] == -1:
                self.backend = Mmap_backend(self.num_bits_m, filename[0])
            else:
                self.backend = Array_then_file_seek_backend(self.num_bits_m, filename[0], filename[1])
        else:
            if start_fresh:
                try_unlink(filename)
            self.backend = File_seek_backend(self.num_bits_m, filename)

        # AKA num_offsetters
        # Verified against http://en.wikipedia.org/wiki/Bloom_filter#Probability_of_false_positives
        if num_hashes is not None:
            self.num_probes_k = num_hashes
        else:
            real_num_probes_k = (self.num_bits_m / self.ideal_num_elements_n) * math.log(2)
            self.num_probes_k = int(math.ceil(real_num_probes_k))
        
        self.probe_bitnoer = probe_bitnoer

    def __repr__(self):
        return 'BloomFilter(ideal_num_elements_n=%d, error_rate_p=%f, num_bits_m=%d, num_probes_k=%d)' % (
            self.ideal_num_elements_n,
            self.error_rate_p,
            self.num_bits_m,
            self.num_probes_k
        )

    def add(self, key):
        """Add an element to the filter"""
        for bitno in self.probe_bitnoer(self, key):
            self.backend.set(bitno)

    def __iadd__(self, key):
        self.add(key)
        return self

    def _match_template(self, bloom_filter):
        """Compare a sort of signature for two bloom filters.  Used in preparation for binary operations"""
        return (self.num_bits_m == bloom_filter.num_bits_m
                and self.num_probes_k == bloom_filter.num_probes_k
                and self.probe_bitnoer == bloom_filter.probe_bitnoer)

    def union(self, bloom_filter):
        """Compute the set union of two bloom filters"""
        self.backend |= bloom_filter.backend

    def __ior__(self, bloom_filter):
        self.union(bloom_filter)
        return self

    def intersection(self, bloom_filter):
        """Compute the set intersection of two bloom filters"""
        self.backend &= bloom_filter.backend

    def __iand__(self, bloom_filter):
        self.intersection(bloom_filter)
        return self

    def __contains__(self, key):
        for bitno in self.probe_bitnoer(self, key):
            if not self.backend.is_set(bitno):
                return False
        return True
