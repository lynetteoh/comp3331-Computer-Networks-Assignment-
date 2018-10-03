
import random
random.seed(100)
with open("random.txt", "w+") as f:
    for i in range(0, 150):
        f.write("count: {} random:{} \n".format(i+1, random.random()))
    

