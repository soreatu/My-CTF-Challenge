def unBitShiftRightXor(value, shift):
    i = 0
    while i * shift < 32:
        part_mask =  ((0xffffffff << (32 - shift)) & 0xffffffff) >> (i * shift)
        part = value & part_mask
        value ^= part >> shift
        i += 1
    return value

def unBitShiftLeftXor(value, shift, mask):
    i = 0
    while i * shift < 32:
        part_mask = ((0xffffffff >> (32 - shift)) & 0xffffffff) << (i * shift)
        part = value & part_mask
        value ^= (part << shift) & mask
        i += 1
    return value

def getState(number):
    number = unBitShiftRightXor(number, 18)
    number = unBitShiftLeftXor(number, 15, 0xefc60000)
    number = unBitShiftLeftXor(number, 7, 0x9d2c5680)
    number = unBitShiftRightXor(number, 11)
    return number

def backtrace(numbers):
    """
    Returns the initial state of the MT PRNG based on list of the output numbers
    """
    # assert(len(numbers) == 624)
    state = []
    for number in numbers:
        state.append(getState(number))
    return state

def getOldStates(states):
    for i in range(3, -1, -1):
        tmp = states[i + 624] ^ states[i + 397]
        if tmp & 0x80000000 == 0x80000000:
            tmp ^= 0x9908b0df
        res = (tmp & 0x40000000) << 1

        tmp = states[i - 1 + 624] ^ states[i + 396]
        if tmp & 0x80000000 == 0x80000000:
            tmp ^= 0x9908b0df
            res |= 1
        res |= (tmp & 0x3fffffff) << 1
        # assert(res == states[i])
        states[i] = res

def next(states, i):
    y = (states[i] & 0x80000000) + (states[(i+1) % 624] & 0x7FFFFFFF)
    n = 0x9908b0df if y & 1 else 0
    res = states[(i+397) % 624] ^ (y >> 1) ^ n
    return res



with open('output.txt', 'r') as f:
    data = f.read()

outputs = [int(output) for output in data.split('\n')[:-1]]
states = [0]*4 + backtrace(outputs)
getOldStates(states)

import random
random.setstate(tuple([3, tuple(states[:624] + [0]), None]))
flag = "flag{" + ''.join(str(random.getrandbits(32)) for _ in range(4)) + "}"
print(flag)
# flag{1886737465387686573924175753923879771350}