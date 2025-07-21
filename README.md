A simple Python program to capture and analyze basic network traffic.
Description

This project provides a lightweight network traffic capturer that monitors and displays incoming and outgoing network packets on your system. It's designed for basic traffic analysis and educational purposes.
Features

Captures incoming and outgoing network packets

Displays basic packet information (source, destination, protocol)

Lightweight and easy to use

Supports common protocols (TCP, UDP, ICMP)
Requirements
    Python 3.6+
    scapy (pip install scapy)
    Administrator/root privileges (for packet capturing)
    Installation

    Clone this repository:
    bash
     git clone https://github.com/yourusername/network-traffic-capturer.git
    cd network-traffic-capturer

Install the required dependencies:
bash

     pip install -r requirements.txt
Usage

Run the traffic capturer with:
bash

    sudo python packet_capturer.py

(Note: Administrative privileges are required for packet capturing)
Configuration

Edit config.ini to:

Set the network interface to monitor

Configure packet filtering options

Adjust verbosity levels
    Output

The program will display captured packets in the console with:

Timestamp

Source IP and port

Destination IP and port

Protocol type

Packet size

Limitations

This is a basic traffic capturer and does not:

    Perform deep packet inspection

    Store captured packets long-term

    Include advanced analysis features
