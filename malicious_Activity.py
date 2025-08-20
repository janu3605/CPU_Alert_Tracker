#Simulates high CPU usage
import time

while True:
    [x**2 for x in range(10_000)]