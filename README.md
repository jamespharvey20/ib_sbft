# ib_sbft - Linux kernel module providing sysfs interface to BIOS sBFT information

Provides a /sys/firmware/sbft directory with information from a sBFT (SRP Boot Firmware Table):
* acpi_oem_id
* acpi_oem_table_id
* acpi_revision
* ib_destination_gid
* ib_partition_key
* ib_service_identifier
* ib_source_gid
* scsi_lun
* srp_initiator_port_identifier
* srp_target_port_identifier

Based on the sBFT specification available at: http://etherboot.org/wiki/srp/sbft

Successfully boots from an SRP volume using:
* iPXE
** Git commit 2afd66eb
** With ipxe/fix_sbft_endian.patch
* srp-boot (https://github.com/jamespharvey20/srp-boot)
* (2) Mellanox ConnectX-2 MT26428, using 2.9.1000 firmware
* Target: Arch Linux, with kernel < 4.7
* Initiator: Arch Linux, with current kernel
