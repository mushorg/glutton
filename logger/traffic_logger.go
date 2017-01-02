package logger

import (
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/mushorg/glutton"
)

var (
	deviceName     string
	snapshotLen    uint32 = 1024
	promiscuous    bool
	err            error
	timeout        time.Duration = -1 * time.Second
	handle         *pcap.Handle
	writer         *pcapgo.Writer
	filename       string
	fileToCompress string
)

const sessionTime = 4 // (Time in hours) This time will swap target pcap file)

// This function create and swap files used by LibPCAP
func swapFiles() {
	for {
		filename = "/var/log/glutton/" + time.Now().String() + ".pcap"
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		glutton.CheckError("[*] Error in creating pcap file", err)
		defer f.Close()
		writer = pcapgo.NewWriter(f)
		writer.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
		if fileToCompress != "" {
			go compressFiles(fileToCompress) //Start compressing of previously used file
		}
		time.Sleep(sessionTime * time.Hour)
		fileToCompress = filename
	}
}

// This function will open selected for live capturing and log traffic of that device to pcap file.
func startCapturing() {
	// Go routine used for creating and swapping file
	go swapFiles()

	// Open Device
	handle, err = pcap.OpenLive(deviceName, int32(snapshotLen), promiscuous, timeout)
	glutton.CheckError("Error opening device", err)
	defer handle.Close()

	// Setting filter for packet capturing
	err = handle.SetBPFFilter("tcp or udp")
	glutton.CheckError("[*] Error: BPF filtering", err)

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Packet capturing started for ", deviceName)

	for packet := range packetSource.Packets() {
		// Writing packets to PCAP
		writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}
}

// FindDevice will search for network interface cards available and select one for logging
func FindDevice(wg *sync.WaitGroup) {
	defer wg.Done()

	log.Println("Checking for previously uncompressed files")
	go checkForUncompressed() // Check the logging directory for uncompressed files
FindAgain:
	// Find all devices
	devices, err := pcap.FindAllDevs()
	glutton.CheckError("Error in search for network interface card.", err)

	interfaceCount := 0
	for _, device := range devices {
		if device.Name == "lo" {
			continue
		}
		if len(device.Addresses) == 2 {
			deviceName = device.Name
			interfaceCount++
		}
	}

	//No interface could be detected
	if interfaceCount == 0 {
		log.Println("No INTERNET connection, trying again... ")
		time.Sleep(30 * time.Second)
		goto FindAgain
	}

	//Only one interface is available
	if interfaceCount == 1 {
		startCapturing()
	} else {
		log.Println("Configuration file to deal with multiple is under implementation!")
	}
}
