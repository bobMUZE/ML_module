from queue import Queue
import pandas as pd
import time
import threading

a = Queue() # a를 수진이쪽이라고 가정
def test1():
    while True:
        v = a.get()
        time.sleep(0.1)
        if v == None:
            print("None")
        else:
            print(v) # class 들어올 예정 코드 확인 후 ok 받으면


t2 = threading.Thread(target=test1, args=())
t2.start()



