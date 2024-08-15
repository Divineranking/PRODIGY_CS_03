# PRODIGY_CS_03
Packet Sniffer
This is a simple packet sniffer script written in Python using the Scapy library. The script captures packets on a specified network interface and logs details about each packet to a CSV file.

Prerequisites
Before you begin, ensure you have the following installed on your machine:

Python 3.6+
pip (Python package installer)
Scapy library
WinPcap or Npcap (for Windows users)
Installation
Clone the Repository:
git clone https://github.com/Divineranking/packetAnalyser.git
cd packetAnalyser
Create and Activate a Virtual Environment (Optional but recommended):
python -m venv my_venv
source my_venv/Scripts/activate  # For Windows
# source my_venv/bin/activate    # For macOS/Linux
Install Required Packages:
Install WinPcap or Npcap (Windows Only):

Download and install Npcap or WinPcap.
Ensure that the library is installed and functioning.
Usage
To run the packet sniffer, use the following command:
python packetAnalyser.py -i <interface_name> -o <output_file.csv> -c <packet_count> -f "<filter_expression>"
python packetAnalyser.py -i <interface_name> -o <output_file.csv> -c <packet_count> -f "<filter_expression>"

