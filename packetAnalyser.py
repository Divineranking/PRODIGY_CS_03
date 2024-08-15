#!/usr/bin/env python3

import argparse
import sys
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTP
import datetime
import signal
import csv


class PacketSniffer:
    def __init__(self, interface, output_file, packet_count, filter_expression):
        self.interface = interface
        self.output_file = output_file
        self.packet_count = packet_count
        self.filter_expression = filter_expression
        self.packets_captured = 0
        self.start_time = None
        self.csv_writer = None
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def start_csv(self):
        self.csv_file = open(self.output_file, 'w', newline='')
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Length', 'Info'])

    def stop_csv(self):
        if self.csv_file:
            self.csv_file.close()

    def packet_callback(self, packet):
        self.packets_captured += 1

        if IP in packet:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            length = len(packet)
            info = ""

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                info = f"TCP {src_port} -> {dst_port}"
                if packet.haslayer(HTTP):
                    info += f" HTTP {packet[HTTP].Method.decode() if packet[HTTP].Method else ''}"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                info = f"UDP {src_port} -> {dst_port}"

            self.csv_writer.writerow([timestamp, src_ip, dst_ip, protocol, length, info])

            logging.info(f"Packet Captured: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {protocol} | {length} bytes")

        if self.packet_count and self.packets_captured >= self.packet_count:
            raise KeyboardInterrupt

    def run(self):
        self.start_time = datetime.datetime.now()
        logging.info(f"Starting packet capture on interface {self.interface}")
        logging.info(f"Capturing {self.packet_count if self.packet_count > 0 else 'infinite'} packets")
        logging.info(f"Filter: {self.filter_expression if self.filter_expression else 'None'}")
        logging.info("Press Ctrl+C to stop the capture")

        self.start_csv()

        try:
            sniff(iface=self.interface, prn=self.packet_callback, filter=self.filter_expression, store=0)
        except KeyboardInterrupt:
            logging.info("\nPacket capture stopped by user.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            self.stop_csv()
            self.print_summary()

    def print_summary(self):
        duration = datetime.datetime.now() - self.start_time
        logging.info(f"\nCapture Summary:")
        logging.info(f"Duration: {duration}")
        logging.info(f"Packets captured: {self.packets_captured}")
        logging.info(f"Output file: {self.output_file}")


def signal_handler(sig, frame):
    logging.info("\nCapture interrupted by user. Cleaning up...")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-o", "--output", default="captured_packets.csv", help="Output file for captured packets")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")
    parser.add_argument("-f", "--filter", help="BPF filter expression")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    sniffer = PacketSniffer(args.interface, args.output, args.count, args.filter)
    sniffer.run()


if __name__ == "__main__":
    main()
