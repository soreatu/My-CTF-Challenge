import hashlib
from functools import reduce
from Crypto.Util.number import *

ms = [getRandomNBitInteger(128) for i in range(8)]
p = reduce(lambda x,y: x*y, ms)
x = getRandomRange(1, p)
cs = [x % m  for m in ms]

flag = "flag{" + hashlib.sha256(str(x).encode()).hexdigest() + "}"
# assert("4b93deeb" in flag)

# ms = [284461942441737992421992210219060544764, 218436209063777179204189567410606431578, 288673438109933649911276214358963643204, 239232622368515797881077917549177081575, 206264514127207567149705234795160750411, 338915547568169045185589241329271490503, 246545359356590592172327146579550739141, 219686182542160835171493232381209438048]
# cs = [273520784183505348818648859874365852523, 128223029008039086716133583343107528289, 5111091025406771271167772696866083419, 33462335595116820423587878784664448439, 145377705960376589843356778052388633917, 128158421725856807614557926615949143594, 230664008267846531848877293149791626711, 94549019966480959688919233343793910003]