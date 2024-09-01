import atexit
from flask import Flask, request, jsonify
import threading
import json
import serial
import re
import logging
import time
from enum import Enum, IntEnum
from dataclasses import dataclass

logger = logging.getLogger(__name__)
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)

CB_INACTIVITY_TIMEOUT_SECONDS = 10

class SystemType(IntEnum):
    AC = 7
    LIGHTS = 2

class Destination(IntEnum):
    CONTROL_BOX = 1
    TABLET = 3

class WeekDay(IntEnum):
    SUNDAY = 64
    MONDAY = 32
    TUESDAY = 16
    WEDNESDAY = 8
    THURSDAY = 4
    FRIDAY = 2
    SATURDAY = 1

class FanMode(IntEnum):
    off = 0
    low = 1
    medium = 2
    high = 3
    auto = 4
    autoAA = 5

class AirConMode(Enum):
    cool = 1
    heat = 2
    vent = 3
    auto = 4
    dry = 5
    myauto = 6

class FreshAirStatus(IntEnum):
    none = 0
    off = 1
    on = 2

class SystemState(IntEnum):
    off = 0
    on = 1

class ZoneState(IntEnum):
    close = 0
    open = 1

class UnitType(IntEnum):
    daikin = 0x11
    panasonic = 0x12
    fujitsu = 0x13
    samsungdvm = 0x19

class ActivationStatus(IntEnum):
    nocode = 0
    expired = 1
    codeenabled = 2

class Registers(IntEnum):
    GLOBAL_ZONE_CONFIG = 0x01
    UNIT_TYPE_ACTIVATION_STATUS = 0x02
    INDIVIDUAL_ZONE_STATE = 0x03
    INDIVIDUAL_ZONE_CONFIG = 0x04
    SYSTEM_STATUS = 0x05
    CONTROL_BOX_2FIRMWARE_VERSION = 0x06
    STATUS_ACK = 0x07
    AIR_CON_ERROR = 0x08
    ACTIVATION_CODE_ENTRY = 0x09
    CONTROL_BOX_EXISTS_NOTIFICATION = 0x0a
    SENSOR_PAIRING = 0x12
    INFO_BYTE = 0x13

@dataclass(frozen=True)
class DirtyRegister():
    id: str
    acuid: str
    register: int
    zone_id: str
    zone_number: int

@dataclass(frozen=True)
class RegisterUpdateFromCB():
    system_type: int
    destination_device: int
    unit_id: str
    register_id: int
    data: list

running = True

# *********************************************************************
# CAN2 XML message parser / generator
# ---------------------------------------------------------------------
# Creates and parses messages of the form <U>msg</U=crc>, as used by 
# the AA control box.
# *********************************************************************
class CanXmlParser:
    message_regex = re.compile("(<U>[A-Za-z0-9 ]+</U=[0-9A-Za-z]{2}>)")
    message_parse_regex = re.compile("<U>([A-Za-z0-9 ]+)</U=([0-9A-Za-z]{2})>")
    max_buffer_size = 2048

    def __init__(self):
        self.data = ""

    # AA CRC8 calculation (init=0x00, final=0xff, poly=0xb2)
    def aacrc8(self,data: bytes):
        crc = 0x00
        for byte in data:
            crc = crc ^ byte
            for j in range(8):
                if (crc & 0x01):
                    crc = (crc >> 1) ^ 0xb2
                else:
                    crc = crc >> 1
        return crc ^ 0xff

    def pass_crc_check_fn(self,msg):
        parse_result = CanXmlParser.message_parse_regex.match(msg)
        if (parse_result):
            msg_crc = int(parse_result.group(2), 16)
            msg_content = parse_result.group(1)
            calculated_crc = self.aacrc8(msg_content.encode("utf-8"))
            return calculated_crc == msg_crc
        else:
            return False

    def extract_msg_from_xml(self,msg):
        parse_result = CanXmlParser.message_parse_regex.match(msg)
        if (parse_result):
            return parse_result.group(1)
        else:
            return msg

    # process bytes read from the serial port; return an array of message bodies.
    def process_incoming_serial_data(self, data):
        self.data += data.decode("utf-8")
        messages = CanXmlParser.message_regex.split(self.data)
        self.data = messages[len(messages)-1]
        if (len(self.data) > CanXmlParser.max_buffer_size):
            self.data = self.data[CanXmlParser.max_buffer_size/2:len(self.data)-1]
        if (len(messages) > 1):
            return map(self.extract_msg_from_xml, filter(self.pass_crc_check_fn, messages[1:len(messages)-1]))
        else:
            return []
    
    def encode_packet(self, data):
        return "<U>{}</U={:02x}>".format(data, self.aacrc8(data.encode("utf-8"))).encode("utf-8")


def format_hex2(val):
    return '{:02x}'.format(val)

lock = threading.Lock()

class Store:
    def __init__(self):
        self.db = {}
        self.dirty_registers = set()

    def initialise(self, filename):
        self.filename = filename
        try:
            json_file = open(filename)
        except FileNotFoundError:
            self.db = { }
        else:
            self.db = json.load(json_file)
            json_file.close()

    def save(self):
        global lock
        try:
            lock.acquire()
            with open(self.filename, 'w') as outfile:
                json.dump(self.db, outfile)
        finally:
            lock.release()

    def process_json_update(self, upd):
        global lock
        try:
            lock.acquire()
            self.db = self.db | upd
            self.update_dirty_registers_based_on_json_update(upd)
            return "Success"
        finally:
            lock.release()

    def build_register_update_message(self, unit_id, register, args):
        zeroed_args = (args + [0,0,0,0,0,0,0])[:7]
        return '{:02X}'.format(SystemType.AC) + '{:02X}'.format(Destination.CONTROL_BOX) + unit_id.lower() +'{:02X}'.format(register) + ''.join(map(format_hex2, zeroed_args))

    def update_dirty_registers_based_on_json_update(self, update):
        global lock
        try:
            lock.acquire()
            # attempt to determine what has changed based on the incoming update, and mark
            # the appropriate CB registers as "dirty" - ie. needing to be pushed to the CB.
            for ackey in update["aircons"]:

                # get the UID of the aircon from the store
                acuid = self.db["aircons"][ackey]["info"]["uid"]

                # determine what has changed in update for this aircon ...

                # if we received an update to the aircons.acXX.info data, then flush system status and global zone config to CB
                if update["aircons"][ackey]["info"]:
                    logger.info("Flushing system status and global zone config for "+ackey)
                    self.dirty_registers.update({ 
                        DirtyRegister(ackey, acuid, Registers.SYSTEM_STATUS, None, None),
                        DirtyRegister(ackey, acuid, Registers.GLOBAL_ZONE_CONFIG, None, None)
                    })

                # check zones for updates and flag each individual zone as dirty if required
                if update["aircons"][ackey]["zones"]:
                    for zonekey in update["aircons"][ackey]["zones"]:
                        zone_number = self.db["aircons"][ackey]["zones"][zonekey]["number"]
                        logger.info("Flushing zone config for "+ackey+"/"+zonekey)
                        self.dirty_registers.update({ 
                            DirtyRegister(ackey, acuid, Registers.INDIVIDUAL_ZONE_CONFIG, zonekey, zone_number),
                            DirtyRegister(ackey, acuid, Registers.INDIVIDUAL_ZONE_STATE, zonekey, zone_number)
                        })
                        if (self.db["aircons"][ackey]["zones"][zonekey]["SensorUid"]):
                            logger.info("Flushing sensor pairing data for zone "+ackey+"/"+zonekey)
                            self.dirty_registers.update({
                                DirtyRegister(ackey, acuid, Registers.SENSOR_PAIRING, zonekey, zone_number)
                            })
        finally:
            lock.release()

    def dirty_all_registers(self):
        global lock
        try:
            lock.acquire()

            logger.info("dirtying all registers - db = " + str(type(self.db)) + "/" + str(self.db))
            # attempt to determine what has changed based on the incoming update, and mark
            # the appropriate CB registers as "dirty" - ie. needing to be pushed to the CB.
            for ackey in self.db["aircons"]:

                # get the UID of the aircon from the store
                acuid = self.db["aircons"][ackey]["info"]["uid"]

                # determine what has changed in update for this aircon ...

                # if we received an update to the aircons.acXX.info data, then flush system status and global zone config to CB
                logger.info("Flushing system status and global zone config for "+ackey)
                self.dirty_registers.update({ 
                    DirtyRegister(ackey, acuid, Registers.SYSTEM_STATUS, None, None),
                    DirtyRegister(ackey, acuid, Registers.GLOBAL_ZONE_CONFIG, None, None)
                })

                # check zones for updates and flag each individual zone as dirty if required
                for zonekey in self.db["aircons"][ackey]["zones"]:
                    zone_number = self.db["aircons"][ackey]["zones"][zonekey]["number"]
                    logger.info("Flushing zone config and zone state for zone "+ackey+"/"+zonekey)
                    self.dirty_registers.update({ 
                        DirtyRegister(ackey, acuid, Registers.INDIVIDUAL_ZONE_CONFIG, zonekey, zone_number),
                        DirtyRegister(ackey, acuid, Registers.INDIVIDUAL_ZONE_STATE, zonekey, zone_number)
                    })
                    if (self.db["aircons"][ackey]["zones"][zonekey]["SensorUid"]):
                        logger.info("Flushing sensor pairing data for zone "+ackey+"/"+zonekey)
                        self.dirty_registers.update({
                            DirtyRegister(ackey, acuid, Registers.SENSOR_PAIRING, zonekey, zone_number)
                        })

        finally:
            lock.release()

    def process_register_update_from_cb(self, upd):
        global lock
        try:
            lock.acquire()
            cb_id = upd.unit_id
            if (self.db["aircons"] is None):
                self.db["aircons"] = {}

            found_ac = False
            ac_id = None
            ac = None
            num_aircons = len(self.db["aircons"])
            for key in self.db["aircons"]:
                if (self.db["aircons"][key]["info"]["uid"] == cb_id):
                    found_ac = True
                    ac = self.db["aircons"][key]

            if not found_ac:
                logger.warning("Received notification from unknown control box; please follow instructions to configure control box with ID: "+cb_id)
                return

            if (upd.register_id == Registers.CONTROL_BOX_EXISTS_NOTIFICATION.value):
                logger.debug("Control box " + upd.unit_id + " exists notification received")
            elif (upd.register_id == Registers.CONTROL_BOX_2FIRMWARE_VERSION.value):
                logger.debug("Control box firmware version notification received - firmware = v" + str(upd.data[0]) + "." + str(upd.data[1]) + "(rf v=" + str(upd.data[3]) + ")")
                ac["info"]["cbFWRevMajor"] = upd.data[0]
                ac["info"]["cbFWRevMinor"] = upd.data[1]
                ac["info"]["unitType"] = upd.data[2]
                ac["info"]["rfFWRevMajor"] = upd.data[3]
            elif (upd.register_id == Registers.GLOBAL_ZONE_CONFIG.value):
                logger.debug("Global zone config received")
                ac["info"]["noOfZones"] = upd.data[1]
                ac["info"]["noOfConstants"] = upd.data[2]
                ac["info"]["constant1"] = upd.data[3]
                ac["info"]["constant2"] = upd.data[4]
                ac["info"]["constant3"] = upd.data[5]
                ac["info"]["filterCleanStatus"] = upd.data[6]
            elif (upd.register_id == Registers.SYSTEM_STATUS.value):
                logger.debug("System status update received")
                ac["info"]["state"] = SystemState(upd.data[0]).name
                ac["info"]["mode"] = AirConMode(upd.data[1]).name
                ac["info"]["fan"] = FanMode(upd.data[2]).name
                ac["info"]["setTemp"] = upd.data[3] / 2.0
                ac["info"]["myZone"] = upd.data[4]
                ac["info"]["freshAirStatus"] = FreshAirStatus(upd.data[5]).name
                ac["info"]["rfSysId"] = upd.data[6]
            elif (upd.register_id == Registers.AIR_CON_ERROR.value):
                error_code = bytes(upd.data).decode()
                logger.error("Received error status code from AC: "+error_code)
                ac["info"]["airconErrorCode"] = error_code
            elif (upd.register_id == Registers.INFO_BYTE.value):
                logger.debug("Received info byte update for AC -- ignoring")
            elif (upd.register_id == Registers.UNIT_TYPE_ACTIVATION_STATUS.value):
                logger.debug("Received activation status update for AC: "+str(upd.register_id))
                ac["info"]["unitType"] = upd.data[0]
                ac["info"]["activationCodeStatus"] = ActivationStatus(upd.data[1]).name
            elif (upd.register_id == Registers.INDIVIDUAL_ZONE_STATE.value):
                zone_num = upd.data[0]
                logger.debug("Received zone state update for AC: "+str(upd.register_id)+"(zone: "+str(zone_num)+")"+" - measured temp = " + str(upd.data[4] + upd.data[5]/10.0))
                zone = self.find_zone(ac, zone_num)
                if (zone is None):
                    logger.warning("Received zone state update for zone "+str(zone_num)+" which is not configured.")
                    return
                zone["state"] = "open" if ((upd.data[1] & 128) == 128) else "closed"
                zone["value"] = upd.data[1] & 127
                zone["type"] = upd.data[2]
                zone["setTemp"] = upd.data[3] / 2.0
                zone["measuredTemp"] = upd.data[4] + upd.data[5]/10.0
            elif (upd.register_id == Registers.INDIVIDUAL_ZONE_CONFIG.value):
                zone_num = upd.data[0]
                logger.debug("Received zone config for AC: "+str(upd.register_id)+"(zone: "+str(zone_num)+")")
                zone = self.find_zone(ac, zone_num)
                if (zone is None):
                    logger.warning("Received zone config update for zone "+str(zone_num)+" which is not configured.")
                    return
                zone["minDamper"] = upd.data[1]
                zone["maxDamper"] = upd.data[2]
                zone["motion"] = upd.data[3]
                zone["motionConfig"] = upd.data[4]
                zone["rssi"] = upd.data[6]
            else:
                print("Received update for unknown register: "+str(upd.register_id))
        finally:
            lock.release()

    def clear_dirty_registers(self):
        global lock
        try:
            lock.acquire()
            self.dirty_registers.clear()
        finally:
            lock.release()

    def get_dirty_register_msg(self):
        global lock
        try:
            lock.acquire()
            
            count = 0

            to_process = set()
            while (len(self.dirty_registers) > 0 and count < 5):
                to_process.add(self.dirty_registers.pop())
                count = count + 1

            if len(to_process) != 0:
                msg = "setCAN"
                for register in to_process:
                    if (register.register == Registers.SYSTEM_STATUS):
                        # `05` - CB JZ14 - System Status
                        #| Byte # | Description |
                        #| ------ | ----------- |
                        #| 0      | System State - On (`01`) or off (`00`) |
                        #| 1      | System Mode (`01`=cool,`02`=heat,`03`=vent,`04`=auto,`05`=dry,`06`=myauto) |
                        #| 2      | System Fan (`00`=off, `01`=low, `02`=medium, `03`=high, `04`=auto, `05`=autoAA) |
                        #| 3      | Set Temp (deg C * 2.0) |
                        #| 4      | MyZone ID (1-10, 0 = default / not enabled??) |
                        #| 5      | Fresh Air Status (`00`=none, `01`=off, `02`=on) |
                        #| 6      | RF Sys ID |
                        msg = msg + " " + self.build_register_update_message(
                            register.acuid, 
                            register.register,
                            [
                                SystemState[self.db["aircons"][register.id]["info"]["state"]].value,
                                AirConMode[self.db["aircons"][register.id]["info"]["mode"]].value,
                                FanMode[self.db["aircons"][register.id]["info"]["fan"]].value,
                                int(self.db["aircons"][register.id]["info"]["setTemp"] * 2.0),
                                self.db["aircons"][register.id]["info"]["myZone"],
                                FreshAirStatus[self.db["aircons"][register.id]["info"]["freshAirStatus"]].value,
                                self.db["aircons"][register.id]["info"]["rfSysID"]
                            ]
                        )
                    elif (register.register == Registers.GLOBAL_ZONE_CONFIG):
                        # `01` - (Tablet to CB) - Zone Config
                        #| Byte # |  Description |
                        #| ---    | ----------- |
                        #| 0      | Hex 0x11 (Decimal 17) -- not sure what this means |
                        #| 1      | # of zones |
                        #| 2      | # of constant zones (0-3) |
                        #| 3      | constant zone 1 |
                        #| 4      | constant zone 2 |
                        #| 5      | constant zone 3 |
                        #| 6      | filter clean status (00 or 01) |
                        msg = msg + " " + self.build_register_update_message(
                            register.acuid, 
                            register.register,
                            [
                                17,
                                self.db["aircons"][register.id]["info"]["noOfZones"],
                                self.db["aircons"][register.id]["info"]["noOfConstants"],
                                self.db["aircons"][register.id]["info"]["constant1"],
                                self.db["aircons"][register.id]["info"]["constant2"],
                                self.db["aircons"][register.id]["info"]["constant3"],
                                self.db["aircons"][register.id]["info"]["filterCleanStatus"]
                            ]
                        )
                    elif (register.register == Registers.INDIVIDUAL_ZONE_CONFIG):
                        # `04` - CB JZ13 - Zone Config
                        #| Byte # | Description |
                        #| --- | ----------- |
                        #| 0   | Zone # (`01`-`0a`) |
                        #| 1   | Min Damper |
                        #| 2   | Max Damper |
                        #| 3   | Motion Status (0-22) |
                        #| 4   | Motion Config (0, 1, 2) |
                        #| 5   | Motion Zone Error |
                        #| 6   | CB RSSI |
                        msg = msg + " " + self.build_register_update_message(
                            register.acuid,
                            register.register,
                            [
                                register.zone_number,
                                self.db["aircons"][register.id]["zones"][register.zone_id]["minDamper"],
                                self.db["aircons"][register.id]["zones"][register.zone_id]["maxDamper"],
                                0,
                                self.db["aircons"][register.id]["zones"][register.zone_id]["motion"],
                                0,
                                0
                            ]
                        )
                    elif (register.register == Registers.INDIVIDUAL_ZONE_STATE):
                        ## `03` - CB JZ11 - Zone State
                        #| Byte # |Description |
                        #| --- | ----------- |
                        #| 0   | Zone # (01-0a) |
                        #| 1   | Bit 7: 1=Zone Open, 0=Zone Closed<br>Bits 6-0: Zone Percent 0-100 |
                        #| 2   | Sensor Type<br>0=No Sensor, 1=RF, 2=Wired, 3=RF2CAN Booster, 4=RF_X|
                        #| 3   | Hex Set Temp * 2.0  (0 - 80 ==> 0-40 degrees C)|
                        #| 4   | Measured Temp Int Portion |
                        #| 5   | Measured Temp Decimal Portion (0-9) |
                        #| 6   | Hex 00 / Ignored |
                        msg = msg + " " + self.build_register_update_message(
                            register.acuid,
                            register.register,
                            [
                                register.zone_number,
                                0 if self.db["aircons"][register.id]["zones"][register.zone_id]["state"] == "close" else 128,
                                self.db["aircons"][register.id]["zones"][register.zone_id]["type"],
                                int(self.db["aircons"][register.id]["zones"][register.zone_id]["setTemp"] * 2.0),
                                0,
                                0,
                                0
                            ]
                        )
                    elif (register.register == Registers.SENSOR_PAIRING):
                        # `12` - Tablet to CB: CB JZ32 - Attach sensor to zone
                        #
                        #| Byte # | Description |
                        #| --- | ----------- |
                        #| 0-2 | Sensor UID  |
                        #| 3   | Zone #      |
                        #| 4-6 | Hex 000000  |
                        sensor_id = self.db["aircons"][register.id]["zones"][register.zone_id]["SensorUid"]
                        msg = msg + " " + self.build_register_update_message(
                            register.acuid,
                            register.register,
                            [
                                int(sensor_id[0:2],16),
                                int(sensor_id[2:4],16),
                                int(sensor_id[4:6],16),
                                register.zone_number,
                                0,
                                0,
                                0
                            ]
                        )
                return msg
            else:
                return None
        finally:
            lock.release()


    def find_zone(self, ac, zone_num):
        found_zone = False
        for key in ac["zones"]:
            if (ac["zones"][key]["number"] == zone_num):
                found_zone = True
                return ac["zones"][key]
        return None

# *********************************************************************
# Global Application State
# *********************************************************************

logging.info("Creating store")
store = Store()
logging.info("Reading store state from DB file")
store.initialise("./db/aircons.db.json")


# *********************************************************************
# CAN Layer: Handle serial comms with the Control Box
# *********************************************************************
class CanLayer:

    def __init__(self, serialPath):
        self.serialPath = serialPath
        self.inactivity_timer = None
        self.reset_timer()
        self.reset()
        self.ser = serial.Serial(serialPath, 57600, timeout=0)
        self.parser = CanXmlParser()
        self.can_connection_state = "DISCONNECTED"

    def reset_timer(self):
        if self.inactivity_timer:
            self.inactivity_timer.cancel()
            self.inactivity_timer = None
        self.inactivity_timer = threading.Timer(CB_INACTIVITY_TIMEOUT_SECONDS, self.__inactive_connection_detected)

    def __inactive_connection_detected(self):
        logger.info("Inactive connected detected")
        self.can_connection_state = "INACTIVE"

    def reset(self):
        self.outbound_message_queue = []

    def shutdown(self):
        self.ser.close()
        self.reset()

    def event_loop_tick(self):
        incoming_serial_data = self.ser.read(1024)
        incoming_messages = self.parser.process_incoming_serial_data(incoming_serial_data)
        for incoming_message in incoming_messages:
            self.process_message(incoming_message)

    # Iterate through dirty registers (ie. things that have been updated by clients of the API), and queue 
    # the updates for synchronisation back to the CB.
    def __enqueue_outbound_register_updates(self):
        global store
        message = store.get_dirty_register_msg()
        if (message):
            logger.info("Sending update message to CB: "+message)
            self.outbound_message_queue.append(message)

    # Process inbound message from the CB
    def process_message(self, msg):
        global store
        self.inactivity_timer.cancel()
        self.inactivity_timer = None

        first_word = msg.split(" ")[0]
        if (msg == "Ping"):
            if (self.can_connection_state == "INACTIVE"):
                logger.info("Connection re-stablished, requesting system data refresh")
                self.ser.write(self.parser.encode_packet("getSystemData"))
                self.can_connection_state = "WAIT_SYSTEMDATA";
            elif (self.can_connection_state == "DISCONNECTED"):
                logger.info("Connection Established, requesting system data")
                self.ser.write(self.parser.encode_packet("getSystemData"))
                self.can_connection_state = "WAIT_SYSTEMDATA";
            elif (self.can_connection_state == "CONNECTED"):
                if (len(self.outbound_message_queue) == 0):
                    self.__enqueue_outbound_register_updates()             
                if (len(self.outbound_message_queue) != 0):
                    next_msg = self.outbound_message_queue.pop(0)
                    logger.debug("Writing message: "+next_msg)
                    self.ser.write(self.parser.encode_packet(next_msg))
        elif (msg == "CAN2 in use"):
            logger.debug("Received CAN2 protocol confirmation from CB.  Sending flush register request. ");
            # make sure first message we send is 'setCAN 0701000000600000000000000', which tells the 
            # CB to follow up with a full register flush.
            self.outbound_message_queue.append("setCAN 0701000000600000000000000")

            # don't care about lights for now
            # self.outbound_message_queue.append("setCAN 0201000000000360000000000")
            # self.outbound_message_queue.append("setCAN 0201000000236000000000000")
            
            # force full flush of all DB data to the DB by marking all registers as dirty (ie. as if a user had just updated them from the API)
            store.dirty_all_registers()
            self.can_connection_state = "CONNECTED"
        elif (first_word == "getCAN"):
            # convert getCAN message into set of register updates, and forward to store
            if (len(msg) > 10):
                logger.debug("getCAN message received: "+msg)

            msg_regex = re.compile('^getCAN ([0-9]+) ([0-9A-Fa-f ]+)$')
            regex_match_result = msg_regex.match(msg)
            if (regex_match_result):
                whole = regex_match_result.group(0)
                id = regex_match_result.group(1)
                payload = regex_match_result.group(2)

                # split getCAN message payload and extract individual register updates
                register_updates = payload.split(" ")

                # process each register separately; create a RegisterUpdate object and
                # dispatch it to the store.
                for register_update in register_updates:
                    logger.info("Checking update")
                    if (len(register_update) == 25):
                        logger.info("Processing update")
                        reg = RegisterUpdateFromCB(
                            int(register_update[0:2], 16),
                            int(register_update[2:4], 16),
                            register_update[4:9],
                            int(register_update[9:11],16),
                            [
                                int(register_update[11:13],16),
                                int(register_update[13:15],16),
                                int(register_update[15:17],16),
                                int(register_update[17:19],16),
                                int(register_update[19:21],16),
                                int(register_update[21:23],16),
                                int(register_update[23:25],16)
                            ]
                        )
                        store.process_register_update_from_cb(reg)
                    elif (register_update != ''):
                        logger.warning("Received getCAN register update that was not of expected length: "+register_update+" \nfull packet: "+msg);
            else:
                logger.warning("getCAN message didn't match expected pattern")
            # save updates to store on disk
            store.save()

            # make sure that the next message sent from the (*cough*) "tablet" (*cough*) to CB is an ACK for the setCAN
            # by injecting ackCAN response at the head of the outbound message queue.
            self.outbound_message_queue.append("ackCAN 1")

        else:
            logger.error("Unknown/unhandled message received: "+msg)


        self.reset_timer()

# *********************************************************************
# Flask API endpoints
# *********************************************************************
 
app = Flask(__name__)

# Ugh, this is horrible, updating state using a GET request.
@app.route("/setAircon", methods=['GET'])
def update_aircon_settings():
    update = json.loads(request.args.get("json"))
    logger.info("Processing request to update aircon state with values "+str(update))
    global store
    data = store.db
    result = store.process_json_update(update)
    success = (result == "Success")
    error_description = result
    return jsonify(
      ack=success,
      reason=error_description
    ), 200 if success else 400, {'Content-Type': 'application/json; charset=utf-8'}

@app.route("/getSystemData", methods=['GET'])
def get_system_data():
    logger.info("Processing request to get system data / current state")
    global store
    data = store.db
    return data, 200, {'Content-Type': 'application/json; charset=utf-8'}

def graceful_shutdown():
    global store
    store.save()
    running = False

atexit.register(graceful_shutdown)

def main_loop():
  can = CanLayer('/dev/cu.usbserial-AB0KOAZB')
  while running:
    can.event_loop_tick()
    time.sleep(0.01)
   
if __name__ == '__main__':
    flask_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=2025, debug=True, use_reloader=False)).start()
    main_loop()
    flask_thread.join()
    print("API has been shut down gracefully.")


