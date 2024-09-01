# Aircons DB file

## About

The `aircons.db.json` file provided here is an example file with sample data.

In order to use this, you'll need to update the config to suit your system:

- `aircons/ac1/info/uid` and `aircons/system/mid` will need to be updated with your CB UID.
- `aircons/ac1/info/(mode|fan|myZone|setTemp|state|noOfConstants|constant1|constant2|constant3|noOfZones)` will need to be updated to match your configuration.
- `aircons/ac1/zones/zXX/(maxDamper|minDamper|name|SensorUid|setTemp|state)` will need to be updated to match your system requirements.

## Detecting CB unit ID

Note: if the software detects a mismatch of the CB, ie. it gets a response from a unit that does not exist in the config file, it will terminate with an error, and the error message will include the unit ID of the CB that was detected.
At a pinch, this could be used to get the UID data needed to populate the `aircons.db.json` config file, although you will still need to update the zone configuration and sensor ID's too.

It should be possible to write a tool to interrogate the CB for UID's of the CB itself, and to display any sensors that it finds nearby, in order to make creation of this file a little easier in case of catastrophic failure.

## Disclaimer

This software is very beta.  Use it at your own risk.

Configuring incorrect settings for things like damper settings and constant zones _may_ adversely impact your A/C.  Please make sure you understand what you're doing before updating config. Ideally you should mirror what your AC installer set up for you by checking these values on your existing config (`GET http://<tablet-ip>:2025/getSystemData`).
